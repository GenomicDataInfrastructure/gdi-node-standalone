//! The `check` command: verify the running service's FDP output matches the
//! package contents.
//!
//! The tool reads the package's `manifest.json` (its FDP-public `metadata`), fetches
//! the dataset's served FDP record (`{service_url}/fairdp/dataset/{id}`), and asserts
//! the key public values are consistent. It runs against S3, taking a concrete id or
//! `--all`/`--hidden`/`--visible`, or against a local `.tar.c4gh` or staging directory for
//! the no-S3 workflow. Either way the service must be running.
//!
//! The comparison lives in [`crate::check`]; this is the orchestrating wrapper.

use std::path::Path;

use gdi_node_standalone_core::id::is_valid_dataset_id;
use gdi_node_standalone_core::model::manifest::Manifest;

use super::cmd_inspect;
use crate::check::{self, CheckReport};
use crate::cli::{CheckArgs, OutputFormat};
use crate::s3::{Store, Visibility};
use crate::scratch::Scratch;
use crate::{ToolError, catalogs, profile, runtime, s3};

use crate::MANIFEST_NAME;

/// Run `check`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when no `service_url` is configured, an S3
/// bucket is required but absent, a manifest cannot be read, the FDP fetch fails,
/// or any checked dataset's values do not match the served FDP output.
pub fn run(
    args: &CheckArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let active = profile::load_active(config_path, profile_name)?;
    let service_url = active.service_url.as_deref().ok_or_else(|| {
        ToolError::user("check needs a `service_url` (the running service to query its FDP output)")
    })?;
    s3::install_crypto_provider();
    // The store is needed only by the S3 selectors; `--local` reads a local artifact and must
    // not demand an `[s3]` block (that is the documented no-S3 workflow).
    let store = if args.local.is_some() {
        None
    } else {
        let s3_cfg = active.s3.as_ref().ok_or_else(|| {
            ToolError::user(
                "check against S3 needs a [profiles.<name>.s3] block (or pass --local <path>)",
            )
        })?;
        crate::output::note(&format!(
            "S3 bucket: {}",
            s3_cfg.bucket.as_deref().unwrap_or("<unset>")
        ));
        Some(s3::build_object_store(s3_cfg)?)
    };
    // The management-plane oracle, when the profile names one. `check` reads the public
    // FDP, which serves visible datasets only, so a 404 there is ambiguous on its own —
    // see `fetch_fdp_dataset`. The same base `node_state_base` resolves, but with the
    // fallback made visible: a `service_url` standing in for an unset `management_url` is
    // the public plane, whose 404 says nothing about the id.
    let oracle = match (
        active.management_url.as_deref(),
        active.service_url.as_deref(),
    ) {
        (Some(base), _) => Some(StateOracle {
            base,
            fallback: false,
        }),
        (None, Some(base)) => Some(StateOracle {
            base,
            fallback: true,
        }),
        (None, None) => None,
    };
    run_with(args, service_url, store.as_ref(), config_path, oracle)
}

/// Where `check` asks the node about a dataset the FDP does not serve, and whether that
/// address is the profile's `management_url` or `service_url` standing in for it.
///
/// The distinction decides what a `404` from the oracle means. From the management plane it
/// is the node's own answer, "never seen this id". From the public plane, the fallback
/// `node_state_base` takes when no `management_url` is set, it is what every id gets, so
/// reading it as the node's verdict would tell a provider whose dataset is merely hidden to
/// re-install it.
#[derive(Debug, Clone, Copy)]
pub struct StateOracle<'a> {
    /// The base URL `GET /datasets/{id}/state` is resolved against.
    pub base: &'a str,
    /// `true` when `base` is the profile's `service_url` because no `management_url` is
    /// set — a `404` there is the public plane's answer, not the node's.
    pub fallback: bool,
}

/// `check` against an already-resolved service URL and (for the S3 selectors) an
/// already-opened store — the same code path [`run`] takes, minus profile resolution.
///
/// The seam exists for the reason `cmd_upload`'s does: without it, everything below the
/// profile needs a real node and a real bucket, so the verb that decides whether a published
/// dataset matches what was packaged would be untestable. Both dependencies are injectable:
/// `service_url` accepts a loopback stub (plaintext `http` is exempt from the HTTPS
/// requirement for loopback), and `store` is `Arc<dyn ObjectStore>`.
///
/// `store` is `None` on the `--local` path, which needs no bucket.
///
/// # Errors
///
/// Returns a [`ToolError`] when a manifest cannot be read, the FDP fetch fails, or any
/// checked dataset disagrees with the served output.
pub fn run_with(
    args: &CheckArgs,
    service_url: &str,
    store: Option<&Store>,
    config_path: Option<&Path>,
    oracle: Option<StateOracle<'_>>,
) -> Result<(), ToolError> {
    let started = std::time::Instant::now();
    crate::output::note(&format!(
        "checking against the service FDP at {service_url}"
    ));

    let text = args.format == OutputFormat::Text;

    // Local-artifact path: read the manifest from a .tar.c4gh or staging dir.
    let reports: Vec<CheckReport> = if let Some(path) = args.local.as_deref() {
        crate::output::note(&format!(
            "reading the local manifest from {}",
            path.display()
        ));
        let manifest = read_local_manifest(path, config_path)?;
        crate::output::note(&format!(
            "checking dataset {} from the local artifact",
            manifest.metadata.dataset_id
        ));
        let report = check_one(service_url, &manifest, oracle)?;
        if text {
            print_report(&report);
        }
        vec![report]
    } else {
        // S3 path: download each selected package and check it.
        let store = store.ok_or_else(|| {
            ToolError::user(
                "check against S3 needs a [profiles.<name>.s3] block (or pass --local <path>)",
            )
        })?;

        let ids = select_s3_ids(store, args)?;
        crate::output::note(&format!(
            "selected {} dataset(s) to check from S3",
            ids.len()
        ));
        if ids.is_empty() {
            // Honour the format even for the empty case (a versioned envelope with an
            // empty `results` array is a valid, parseable "checked nothing").
            match args.format {
                OutputFormat::Json => {
                    let out = serde_json::json!({ "schemaVersion": 1, "results": [] });
                    crate::output::emit_json(&out);
                }
                OutputFormat::Text => println!("(no datasets selected to check)"),
            }
            return Ok(());
        }

        let mut reports = Vec::with_capacity(ids.len());
        let total = ids.len();
        // A discrete per-dataset count bar. Live only in JSON mode: in text mode each
        // report prints to stdout during the loop, so off-TTY `step` keeps the plain
        // `checking N/total: id` stderr line instead of a bar that would fight that output.
        let cp = crate::progress::CountProgress::new(
            "checking",
            total as u64,
            crate::progress::active() && !text,
        );
        for id in &ids {
            cp.step(id);
            // Record a per-dataset failure as an outcome rather than propagating it.
            // `--all` selects hidden ids too and the node serves the FDP dataset route only
            // for a Visible dataset, so a normal bucket structurally contains ids that 404;
            // aborting on the first would discard every prior result and, in `--format
            // json`, suppress the whole envelope. `finish` still decides the exit code.
            let report = match download_manifest(store, id, config_path)
                .and_then(|manifest| check_one(service_url, &manifest, oracle))
            {
                Ok(report) => report,
                Err(e) => CheckReport {
                    id: id.clone(),
                    fields: Vec::new(),
                    unavailable: Some(e.to_string()),
                },
            };
            if text {
                print_report(&report);
            }
            reports.push(report);
        }
        cp.finish();
        reports
    };

    if !text {
        let out = serde_json::json!({ "schemaVersion": 1, "results": reports });
        crate::output::emit_json(&out);
    }
    let mismatched = reports.iter().filter(|r| !r.all_ok()).count();
    crate::output::note(&format!(
        "checked {} dataset(s) ({mismatched} mismatched) in {:.1?}",
        reports.len(),
        started.elapsed()
    ));
    finish(&reports)
}

/// Select the S3 dataset ids to check from the args (a concrete id, or a
/// visibility filter / `--all`).
fn select_s3_ids(store: &Store, args: &CheckArgs) -> Result<Vec<String>, ToolError> {
    if let Some(id) = args.id.as_deref() {
        if !is_valid_dataset_id(id) {
            return Err(ToolError::user(format!("invalid dataset id: {id}")));
        }
        return Ok(vec![id.to_owned()]);
    }
    let listed = runtime::block_on(s3::list_datasets(store))?;
    let ids = listed
        .into_iter()
        .filter(|d| match (args.visible, args.hidden) {
            (true, _) => d.visibility == Visibility::Visible,
            (_, true) => d.visibility == Visibility::Hidden,
            _ => true, // --all (or no filter): every dataset.
        })
        .map(|d| d.id)
        .collect();
    Ok(ids)
}

/// Download `{id}.tar.c4gh` from S3 and read its `manifest.json`.
fn download_manifest(
    store: &Store,
    id: &str,
    config_path: Option<&Path>,
) -> Result<Manifest, ToolError> {
    // 8 MiB comfortably covers any realistic manifest plus the crypt4gh header/segment
    // overhead; the manifest reader early-stops after the first member.
    const MANIFEST_HEAD_BYTES: u64 = 8 * 1024 * 1024;
    // Stage the package inside a `0o700` scratch directory (the tool's temp
    // discipline; see Scratch) — never a predictable, world-readable `/tmp` path that
    // could follow a pre-planted symlink. Stream the download straight to the scratch
    // file rather than buffering the whole (possibly multi-GB) encrypted package in
    // RAM: only its first member (manifest.json) is needed. The scratch dir + its
    // contents are removed on drop.
    let scratch = Scratch::new(&std::env::temp_dir().join(id))?;
    let tmp = scratch.path().join("package.tar.c4gh");
    if crate::output::is_verbose() {
        crate::output::note(&format!(
            "downloading package {id} from S3 to read its manifest"
        ));
    }
    // Fetch only the front of the package (crypt4gh header + the leading `manifest.json`
    // tar member) via a ranged GET, rather than downloading the whole (potentially
    // multi-GB) package to scratch just to read its small manifest.
    runtime::block_on(s3::download_package_head_to_path(
        store,
        id,
        &tmp,
        MANIFEST_HEAD_BYTES,
    ))?;
    let json = cmd_inspect::read_manifest_json(&tmp, config_path)?;
    parse_manifest(&json)
}

/// Read a manifest from a local artifact: a `.tar.c4gh` package (decrypt + read
/// the first member) or a staging directory (`manifest.json`).
fn read_local_manifest(path: &Path, config_path: Option<&Path>) -> Result<Manifest, ToolError> {
    if path.is_dir() {
        let manifest_path = path.join(MANIFEST_NAME);
        let json = std::fs::read_to_string(&manifest_path).map_err(|e| {
            ToolError::user(format!("cannot read {}: {e}", manifest_path.display()))
        })?;
        parse_manifest(&json)
    } else if path.is_file() {
        let json = cmd_inspect::read_manifest_json(path, config_path)?;
        parse_manifest(&json)
    } else {
        Err(ToolError::user(format!(
            "local artifact not found: {}",
            path.display()
        )))
    }
}

/// Parse a `manifest.json` string into the typed [`Manifest`].
fn parse_manifest(json: &str) -> Result<Manifest, ToolError> {
    serde_json::from_str(json)
        .map_err(|e| ToolError::user(format!("cannot parse manifest.json: {e}")))
}

/// Fetch a dataset's FDP record and compare it against the package metadata.
fn check_one(
    service_url: &str,
    manifest: &Manifest,
    oracle: Option<StateOracle<'_>>,
) -> Result<CheckReport, ToolError> {
    if crate::output::is_verbose() {
        crate::output::note(&format!(
            "fetching the served FDP record for {} from {}/fairdp/dataset/{}",
            manifest.metadata.dataset_id,
            service_url.trim_end_matches('/'),
            manifest.metadata.dataset_id
        ));
    }
    let body = runtime::block_on(fetch_fdp_dataset(
        service_url,
        &manifest.metadata.dataset_id,
        oracle,
    ))?;
    Ok(check::check_against_fdp(&manifest.metadata, &body))
}

/// Fetch `{service_url}/fairdp/dataset/{id}` as Turtle.
///
/// A non-success response is reported through the management-plane state oracle when
/// `oracle` names one. The FDP dataset route serves visible datasets only, so its 404
/// is the same answer for a dataset that is hidden, one that errored, and one the node has
/// never seen — three states with three different next actions. `upload`/`deploy` land a
/// dataset hidden by design, so running `check` before `publish` is the most likely way to
/// meet it, and the tool can ask the node which of the three it is rather than guessing.
async fn fetch_fdp_dataset(
    service_url: &str,
    id: &str,
    oracle: Option<StateOracle<'_>>,
) -> Result<String, ToolError> {
    let url = format!("{}/fairdp/dataset/{id}", service_url.trim_end_matches('/'));
    // A MITM over plaintext http could serve forged FDP metadata that masks a real
    // ingest mismatch, so `check` would falsely print OK — defeating the command's whole
    // purpose. Require https for a non-loopback host, as the catalog fetch does.
    crate::recipient::require_secure_transport(
        &url,
        "a MITM could serve forged FDP metadata that masks a real mismatch, so `check` would falsely pass.",
    )?;
    let client = catalogs::fdp_client()?;
    let resp = client
        .get(&url)
        .header(reqwest::header::ACCEPT, "text/turtle")
        .send()
        .await
        .map_err(|e| ToolError::user(format!("cannot reach the FDP dataset {url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(ToolError::user(format!(
            "the service does not serve dataset {id} (FDP {url} returned {}){}",
            resp.status(),
            explain_unserved(id, oracle).await
        )));
    }
    // Cap the body so a hostile/MITM'd node cannot OOM the host during `check`.
    catalogs::read_capped_body(resp, &url).await
}

/// Why the FDP does not serve `id`, asked of the node rather than guessed.
///
/// Returns a trailing clause for the error message. Best-effort by construction: with no
/// oracle, an oracle that does not answer, or one that is the public plane standing in
/// for an unset `management_url`, it names the two possibilities rather than inventing
/// one. It never turns a `check` failure into a success — it only says which failure it
/// is.
///
/// Asked through [`crate::state::probe_node_state_detailed`], which keeps "the oracle did
/// not answer" ([`crate::state::NodeProbe::Unreachable`]) apart from "the oracle answered
/// 404" ([`crate::state::NodeProbe::Unknown`]). The plain probe folds both into `None`, and
/// reading that `None` as "the node has never seen this id" would tell a provider whose
/// dataset is merely hidden — behind a firewalled management plane, or behind the public
/// plane a `service_url` fallback points at, which answers 404 for every id — to re-install
/// it.
async fn explain_unserved(id: &str, oracle: Option<StateOracle<'_>>) -> String {
    use crate::state::NodeProbe;

    const CONFIGURE: &str = ": it must be visible and ingested. Configure `management_url` on \
                             the profile and re-run to have `check` report the node's own \
                             answer.";
    let Some(oracle) = oracle else {
        return CONFIGURE.to_owned();
    };
    match crate::state::probe_node_state_detailed(oracle.base, id).await {
        Ok(NodeProbe::Live(state)) if state.is_hidden() => {
            format!(
                ": the node has it hidden, which is where `upload`/`deploy` leave a new dataset. Run `publish {id}`, then re-run `check`."
            )
        }
        Ok(NodeProbe::Live(state)) if state.is_error() => format!(
            ": the node rejected it: {}. Fix the package and re-present it with `--replace`.",
            state
                .error_message
                .as_deref()
                .unwrap_or("no reason reported by the node")
        ),
        Ok(NodeProbe::Live(state)) => format!(
            ": the node reports state `{}`; the FDP dataset route serves visible datasets only.",
            state.state
        ),
        Ok(NodeProbe::Gone(reason)) => {
            format!(": the node has deleted this id and refuses a re-drop: {reason}.")
        }
        // A 404 from the management plane is the node's own answer. From the public plane
        // it is what every id gets, so say what was asked and how to ask the node.
        Ok(NodeProbe::Unknown) if oracle.fallback => format!(
            ": it must be visible and ingested. No `management_url` is set, so `check` asked \
             the service at {}, the public plane, which answers 404 for every id there. \
             Configure `management_url` on the profile and re-run to have `check` report \
             the node's own answer.",
            oracle.base
        ),
        Ok(NodeProbe::Unknown) => {
            ": the node has never seen this id. Install it first (`upload` or `deploy`).".to_owned()
        }
        Ok(NodeProbe::Unreachable) => format!(
            ": it must be visible and ingested (the management plane at {} did not answer, \
             so the node's own state could not be read).",
            oracle.base
        ),
        // A config error — plaintext http to a non-loopback host, a malformed base — is
        // the operator's to fix; name it rather than folding it into "did not answer".
        Err(e) => format!(
            ": it must be visible and ingested (the state oracle at {} could not be asked: {}).",
            oracle.base, e.message
        ),
    }
}

/// Print a per-dataset report (the field results).
fn print_report(report: &CheckReport) {
    if let Some(reason) = &report.unavailable {
        println!(
            "UNAVAILABLE {}: {}",
            crate::output::Untrusted(&report.id),
            crate::output::Untrusted(reason)
        );
        return;
    }
    // Every provider-controlled string on this path goes through `Untrusted`, the same
    // chokepoint `inspect`, `lint` and `preview` use: the id and each field value come
    // straight out of a manifest an untrusted provider wrote, so terminal escapes in one
    // could overwrite the `MISMATCH` verdict this command exists to report.
    let mark = if report.all_ok() { "OK" } else { "MISMATCH" };
    println!("{}: {mark}", crate::output::Untrusted(&report.id));
    for f in &report.fields {
        let m = if f.ok { "ok" } else { "MISMATCH" };
        println!(
            "  {:<14} {m}\t{}",
            f.field,
            crate::output::Untrusted(&f.expected)
        );
    }
}

/// Exit cleanly if all reports passed, else a single error naming the failures.
fn finish(reports: &[CheckReport]) -> Result<(), ToolError> {
    let failed: Vec<&str> = reports
        .iter()
        .filter(|r| !r.all_ok())
        .map(|r| r.id.as_str())
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(ToolError::user(format!(
            "FDP output does not match the package for: {}",
            failed.join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "GDI-EE-UTARTU-20260409143052837";

    /// The clause for `oracle`, off the tool's own runtime (`block_on` wants a `Result`).
    fn explain(oracle: Option<StateOracle<'_>>) -> String {
        crate::runtime::block_on(async { Ok::<_, ToolError>(explain_unserved(ID, oracle).await) })
            .expect("runtime")
    }

    /// A loopback address nothing listens on: bound, read, and released.
    fn dead_base() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        format!("http://{addr}")
    }

    /// An oracle that does not answer must not be read as "the node has never seen this
    /// id".
    #[test]
    fn an_unreachable_oracle_is_reported_as_unanswered_not_as_never_seen() {
        let base = dead_base();
        let clause = explain(Some(StateOracle {
            base: &base,
            fallback: false,
        }));
        assert!(
            clause.contains("did not answer"),
            "an unreachable oracle must be named as such: {clause}"
        );
        assert!(
            !clause.contains("never seen"),
            "an unreachable oracle says nothing about the id: {clause}"
        );
    }

    /// A 404 from the management plane is the node's own answer.
    #[test]
    fn a_404_from_the_management_plane_means_never_seen() {
        let base = test_util::serve_once("", 404, "text/plain");
        let clause = explain(Some(StateOracle {
            base: &base,
            fallback: false,
        }));
        assert!(clause.contains("never seen this id"), "{clause}");
    }

    /// A 404 from `service_url` standing in for an unset `management_url` is the public
    /// plane's answer for every id, so the clause must say what was asked — not invent
    /// a verdict about the dataset.
    #[test]
    fn a_404_from_the_service_url_fallback_names_the_missing_management_url() {
        let base = test_util::serve_once("", 404, "text/plain");
        let clause = explain(Some(StateOracle {
            base: &base,
            fallback: true,
        }));
        assert!(clause.contains("management_url"), "{clause}");
        assert!(
            !clause.contains("never seen"),
            "the public plane's 404 is not a verdict on the id: {clause}"
        );
    }
}
