//! The `list` command: list datasets in the active profile's S3 bucket, with
//! visibility from the `{id}.state.json` sidecars (`all` default / `--visible` /
//! `--hidden`).
//!
//! `list` reads only the bucket. It does not probe the service per id, which is `status`'s
//! job, and there is no `--error`: the `{id}.state.json` sidecars hold only
//! `visible`/`hidden`, while the node's `error` and `processing` states live in the
//! `_status/*` writeback objects. Node `_status/*` objects and the `_sync_marker.json` are
//! ignored.
//!
//! The op logic lives in [`crate::s3`]; this is the thin clap wrapper.

use std::path::Path;

use crate::cli::{ListArgs, OutputFormat};
use crate::s3::Visibility;
use crate::{ToolError, profile, runtime, s3};

/// Run `list`.
///
/// # Errors
///
/// Returns a [`ToolError`] when the profile has no `[s3]` block (exit 1) or any S3
/// listing / sidecar fetch fails; the failure's class sets the exit code —
/// denied/unauthenticated exits 4 (auth), throttled/retry-exhausted exits 3
/// (transient), otherwise exit 1.
pub fn run(
    args: &ListArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let active = profile::load_active(config_path, profile_name)?;
    let store = s3::open_store(&active, "list")?;
    let target = active.s3.as_ref().map(crate::s3::target_label);
    let found = run_with_store(args, &store, target.as_deref())?;
    if found == 0 {
        warn_if_datasets_sit_outside_the_prefix(&active);
    }
    Ok(())
}

/// An empty listing is the one signal a prefix desync gives the writer, and on its own it
/// is indistinguishable from an empty bucket: `list` prints nothing and exits 0 while the
/// node serves the very datasets it cannot see. The node warns in one direction only, for a
/// writer-prefixed key it can see below its own keyspace (`note_nested_dataset_key`). This
/// tool-side probe covers both directions, including a tool with no prefix against a
/// node-prefixed channel, where `list_datasets` recognises root keys only and sees zero.
///
/// Costs one extra listing, and only on the empty result, where there was nothing to
/// report anyway.
fn warn_if_datasets_sit_outside_the_prefix(active: &gdi_node_standalone_core::config::Profile) {
    let Some(s3) = active.s3.as_ref() else {
        return;
    };
    let mut whole_bucket = active.clone();
    if let Some(cfg) = whole_bucket.s3.as_mut() {
        cfg.prefix = String::new();
    }
    let Ok(store) = s3::open_store(&whole_bucket, "list") else {
        return;
    };
    // The whole bucket, nested keys included — not `list_datasets`, which recognises root
    // keys only. A writer on `provider-a` against a node on `provider-b` has a populated
    // prefix of its own and a bare root, so a root-only probe would see nothing wrong while
    // the node ingests nothing.
    let Ok(elsewhere) = runtime::block_on(s3::dataset_locations(&store)) else {
        return;
    };
    let total: usize = elsewhere.values().sum();
    if total == 0 {
        return;
    }
    let where_ = elsewhere
        .keys()
        .map(|p| {
            if p.is_empty() {
                "the bucket root".to_owned()
            } else {
                format!("'{p}'")
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let here = if s3.prefix.trim().is_empty() {
        "at the bucket root".to_owned()
    } else {
        format!("under prefix '{}'", s3.prefix)
    };
    crate::output::warn(&format!(
        "warning: no datasets {here}, but {total} elsewhere in the bucket ({where_}). \
         A prefix set on one side only, or set differently on each, is a desync in which \
         every signal is a success: uploads land where the node never lists. Check it against \
         the node's [[s3.buckets]].prefix for this channel"
    ));
}

/// `list` against an already-opened store — the same code path [`run`] takes, minus profile
/// resolution. See [`crate::commands::cmd_upload::run_with_store`] for why this seam exists.
///
/// # Errors
///
/// Returns a [`ToolError`] when any S3 listing / sidecar fetch fails; the failure's class
/// sets the exit code. On success, the number of datasets the bucket held (before the
/// `--visible`/`--hidden` filter) — zero is what [`run`] follows up on.
pub fn run_with_store(
    args: &ListArgs,
    store: &s3::Store,
    target: Option<&str>,
) -> Result<usize, ToolError> {
    let started = std::time::Instant::now();
    if let Some(label) = target {
        crate::output::note(&format!("listing {label}"));
    }
    let datasets = runtime::block_on(s3::list_datasets(store))?;
    crate::output::note(&format!(
        "listed {} dataset(s) in the bucket",
        datasets.len()
    ));

    let shown: Vec<_> = datasets
        .iter()
        .filter(|d| match (args.visible, args.hidden) {
            (true, _) => d.visibility == Visibility::Visible,
            (_, true) => d.visibility == Visibility::Hidden,
            _ => true,
        })
        .collect();
    let filter = if args.visible {
        "visible"
    } else if args.hidden {
        "hidden"
    } else {
        "all"
    };
    crate::output::note(&format!(
        "filter: {filter}; showing {} of {}",
        shown.len(),
        datasets.len()
    ));

    match args.format {
        OutputFormat::Text => {
            for d in &shown {
                println!("{}\t{}", d.id, d.visibility.as_str());
            }
        }
        OutputFormat::Json => {
            let arr: Vec<_> = shown
                .iter()
                .map(|d| serde_json::json!({ "id": d.id, "visibility": d.visibility.as_str() }))
                .collect();
            let out = serde_json::json!({ "schemaVersion": 1, "datasets": arr });
            crate::output::emit_json(&out);
        }
    }
    crate::output::note(&format!("list complete in {:.1?}", started.elapsed()));
    Ok(datasets.len())
}
