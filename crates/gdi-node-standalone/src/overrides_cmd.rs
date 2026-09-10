//! `overrides export` / `overrides import` / `overrides prune-reingest` — back up,
//! restore, and sweep the operator-override store.
//!
//! The store under `[service].override_dir` is the one thing on the data volume that a
//! re-ingest cannot rebuild: re-ingest restores each dataset to its *source-resolved*
//! state, which is precisely the state an operator overrode. Both loaders treat an
//! unreadable root as the empty set (a node that never suppressed anything is
//! indistinguishable on disk from one whose store was destroyed), so its loss presents as
//! a clean, successful recovery in which every withheld dataset is served again.
//!
//! [`gdi_node_standalone_core::override_store::ensure_present`] tells the operator to
//! "Restore the store from backup"; these subcommands are that procedure.
//!
//! A subcommand rather than a shell script: the backup substrate differs per deployment (a
//! PVC snapshot, a Docker volume, a directory on a host), so anything that shells out would
//! have to guess. A binary that reads its own config works identically everywhere.
//!
//! ## Scope
//!
//! Exactly the directories [`override_store::loader_dirs`] names — `suppressions/` and
//! `overlays/` — derived from that function rather than restated here, so a third loader
//! directory flows into the backup without a code change. `reingest/` is excluded: a marker
//! is a transient request rather than durable operator intent, the same reason
//! `override_store::is_populated` ignores them. `overrides prune-reingest` sweeps the ones
//! this node can no longer act on, since processing keeps a marker so a shared store fans out
//! to every replica and nothing else removes them.
//!
//! ## Bundle format
//!
//! A single JSON document rather than a tar: a disaster-recovery artifact you cannot read
//! is one you cannot verify before trusting it. Entries are stored parsed, so the bundle is
//! diffable and a corrupt store file is named at export time rather than at the next boot.

use std::collections::BTreeMap;
use std::path::Path;
use tracing::warn;

use anyhow::{Context as _, Result, bail};
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::override_store;
use gdi_node_standalone_core::reingest_request;
use serde::{Deserialize, Serialize};

/// Bundle schema version. Bump when the shape changes; `import` refuses anything else
/// rather than guessing at a format it does not know.
const BUNDLE_VERSION: u32 = 2;

/// A portable snapshot of the operator-override store.
#[derive(Debug, Serialize, Deserialize)]
#[expect(
    clippy::struct_field_names,
    reason = "`bundle_version` mirrors the wire key `bundleVersion` (serde-renamed); renaming the field would desync the two"
)]
struct Bundle {
    #[serde(rename = "bundleVersion")]
    bundle_version: u32,
    /// Loader-directory name (`suppressions`, `overlays`) -> file name -> file content.
    ///
    /// Keyed by directory name rather than a fixed pair of fields so the bundle tracks
    /// `loader_dirs` automatically. `BTreeMap` for both levels: a backup that reorders
    /// itself between runs cannot be diffed against the previous one.
    stores: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    /// The append-only re-exposure justification records from `<override_dir>/lifted/`
    /// (`lift_record`), file name -> content. Not a loader store: the node never reads it,
    /// `is_populated` ignores it, and importing it re-creates the audit trail without making
    /// anything in-force. Present only in `bundleVersion` 2 and later; empty, and omitted,
    /// on a node that has never lifted a withhold. It is the only durable off-volume home for
    /// the lift justification, so `export` must capture it or an override-volume loss
    /// destroys it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    history: BTreeMap<String, serde_json::Value>,
}

/// The key a loader directory contributes to the bundle: its final path component.
fn store_key(dir: &Path) -> Result<String> {
    dir.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .with_context(|| {
            format!(
                "override store directory has no usable name: {}",
                dir.display()
            )
        })
}

/// Reject anything that is not a plain `*.json` file name.
///
/// Import writes paths taken from a file it was handed, so a bundle carrying
/// `../../etc/cron.d/x` would otherwise escape the store entirely. The store's own writers
/// only ever produce `{id}.json` / `channel-{name}.json` / `{id}.json`, so this rejects
/// everything a legitimate bundle cannot contain: separators, parent components, absolute
/// paths, and anything not ending in `.json`.
fn validate_entry_name(name: &str) -> Result<()> {
    let looks_like_a_path = name.contains('/')
        || name.contains('\\')
        || name.contains(std::path::MAIN_SEPARATOR)
        || Path::new(name).components().count() != 1;
    if name.is_empty() || looks_like_a_path || name == "." || name == ".." {
        bail!(
            "refusing to import entry {name:?}: entries must be plain file names, and this \
             one would write outside the override store"
        );
    }
    if !Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        bail!("refusing to import entry {name:?}: the override store holds only *.json files");
    }
    Ok(())
}

/// Read one loader directory into a name -> value map.
///
/// An unreadable directory is an error, not an empty map. The loaders treat unreadable as
/// empty because they must keep serving, but a backup that silently captured nothing would
/// be worse than no backup at all.
fn read_store(dir: &Path) -> Result<BTreeMap<String, serde_json::Value>> {
    let mut out = BTreeMap::new();
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read override store directory {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("cannot list {}", dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            bail!(
                "override store file has a non-UTF-8 name: {}",
                path.display()
            );
        };
        if !path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&text).with_context(|| {
            format!(
                "{} is not valid JSON. The loaders fail closed on this file, so it keeps \
                 hiding, but it cannot be captured in a readable backup. Fix or remove it, \
                 then export again",
                path.display()
            )
        })?;
        out.insert(name.to_owned(), value);
    }
    Ok(out)
}

/// Like [`read_store`], but tolerating an absent directory as empty. `lifted/` legitimately
/// does not exist on a node that has never lifted a withhold, so its absence is not the
/// "silently captured nothing" hazard `read_store` guards against. An unreadable-but-present
/// directory, or a corrupt entry, still errors.
fn read_history(dir: &Path) -> Result<BTreeMap<String, serde_json::Value>> {
    match std::fs::metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e).with_context(|| format!("cannot stat {}", dir.display())),
        Ok(_) => read_store(dir),
    }
}

/// Create an empty operator-override store when absent; attest an emptied one (`--yes`).
///
/// The counterpart to `override_store::ensure_present`, which creates nothing: that
/// assertion must be a pure function of a filesystem it did not touch, or a re-provisioned
/// empty volume passes it and every operator withhold is silently lifted. The cost is that a
/// node declaring `require_override_store` before it has ever recorded an override has no
/// store to assert, which is what the create arm is for.
///
/// The attest arm is the other half of the used marker (`crate::override_marker`). A store
/// that is intact but empty while the data volume records that overrides have existed is
/// byte-identical to a structure-only restore that dropped every withhold, and boot refuses
/// it. Running `init --yes` there is the operator declaring the store empty, and the marker
/// is cleared so the node boots. The same marker over an absent store is the lost-volume
/// shape too, so the create arm demands `--yes` there as well, then creates and attests in
/// one run rather than failing the next boot on the marker.
///
/// `--yes` is required rather than recommended, so this verb can never be the reflex answer
/// to a node that will not boot after losing its override volume. The answer there is
/// `overrides import` from the backup described in `docs/operating.md` §17; initialising an
/// empty store instead is the silent re-disclosure the flag exists to prevent.
///
/// Idempotent on an intact store: an already-initialised store, populated or empty with no
/// marker, is a successful no-op that writes nothing. That makes the verb safe to run
/// unattended on every start, which is what `deploy/kubernetes` does with it as an init
/// container so a fresh cluster's first boot works under `require_override_store`. The
/// refusals are unaffected: an absent or emptied store under a standing used marker still
/// stops the node instead of re-serving every withheld dataset.
///
/// # Errors
///
/// Returns an error when the marker stands and `yes` is false, or when the directories
/// cannot be created.
pub fn init(config: &ServiceConfig, yes: bool) -> Result<()> {
    let root = config.service.override_dir_resolved();
    let marker_stands = crate::override_marker::marker_path(config).exists();
    if override_store::is_present(&root) {
        if override_store::is_populated(&root) || !marker_stands {
            // Nothing to do, and that is a success rather than an error: bailing would make
            // the verb non-idempotent, so an unattended `overrides init` would exit non-zero
            // from the second start onwards and hold the pod down. This is not the
            // lost-volume shape — the store is present, with no marker claiming it ever held
            // anything — and the refusals that guard that shape are below. Neither the store
            // nor the marker is written here.
            println!(
                "the operator-override store at {} is already intact; nothing to \
                 initialise. If this node has lost its override volume, `overrides init` \
                 is never the answer: restore it with `overrides import` from the backup, \
                 or every withheld dataset is re-served",
                root.display()
            );
            return Ok(());
        }
        require_attestation(
            &root,
            "intact and empty",
            "attest that it is meant to be empty",
            yes,
        )?;
        crate::override_marker::clear(config);
        println!(
            "the operator-override store at {} is intact and empty, but this node's data \
             volume recorded that overrides have existed. Attested the empty store and \
             cleared the marker; the node will boot. If the store was in fact lost, stop \
             and restore it with `overrides import` instead, or every withheld dataset is \
             re-served",
            root.display()
        );
        return Ok(());
    }
    if marker_stands {
        require_attestation(
            &root,
            "absent",
            "create an empty store and attest that it is meant to be empty",
            yes,
        )?;
    }
    // One call materialises both loader directories: `create_store_dir` derives them from
    // the root, so a third store added later flows in without touching this verb.
    override_store::create_store_dir(&gdi_node_standalone_core::suppression::suppressions_subdir(
        &root,
    ))
    .with_context(|| format!("creating the override store under {}", root.display()))?;
    if marker_stands {
        crate::override_marker::clear(config);
        println!(
            "initialised an empty operator-override store at {}, attested it and cleared \
             the marker; the node will boot. If the store was in fact lost, stop and \
             restore it with `overrides import` instead",
            root.display()
        );
    } else {
        println!(
            "initialised an empty operator-override store at {}",
            root.display()
        );
    }
    Ok(())
}

/// The `--yes` gate shared by both attest shapes (absent, and intact-but-empty), so the
/// two refusals name the same recovery and cannot drift.
fn require_attestation(root: &Path, shape: &str, with_yes: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    anyhow::bail!(
        "the operator-override store at {} is {shape}, but this node's data volume records \
         that overrides have existed. This looks like a lost override volume, and an empty \
         store would silently re-serve every withheld dataset and re-ingest every erased \
         one. Restore it with `overrides import` from the backup. Only if the store is \
         meant to be empty, re-run with --yes to {with_yes}, which clears the marker so the \
         node boots",
        root.display()
    )
}

/// Remove reingest-request markers the node can no longer act on.
///
/// Processing a marker does not delete it — a shared override store would otherwise make a
/// request single-consumer, and every node but the first would miss it (see
/// `gdi_node_standalone_core::reingest_request`). Markers are bounded (one per dataset,
/// rewritten in place) but they do accumulate, and a marker for a dataset that has since
/// been erased lingers forever, reading like pending work during an incident. This is the
/// operator-side broom; the serving path never writes this store.
///
/// Conservative by default: a marker is removed only when the node has no trace of its
/// dataset, neither a directory under `data_dir` nor an entry in the status index. A marker
/// for a live dataset is left alone, because another replica may not have observed it yet,
/// and withdrawing it there would silently deny that replica the request. `--all` overrides
/// that, for an operator withdrawing everything.
///
/// # Errors
///
/// Returns an error when the status index cannot be read, or when a marker cannot be
/// removed (other than being already absent).
pub fn prune_reingest(config: &ServiceConfig, all: bool, dry_run: bool) -> Result<()> {
    let root = config.service.override_dir_resolved();
    let dir = reingest_request::requests_subdir(&root);
    let data_dir = &config.service.data_dir;
    let status = StatusIndex::load(&data_dir.join(".status.json"))
        .with_context(|| format!("reading the status index under {}", data_dir.display()))?;

    let mut removed = 0usize;
    let mut kept = 0usize;
    for id in reingest_request::list_ids(&dir) {
        let known = status.get(&id).is_some() || data_dir.join(&id).is_dir();
        if known && !all {
            kept += 1;
            continue;
        }
        if dry_run {
            println!("dry-run: would remove {id}");
        } else {
            reingest_request::remove_marker(&dir, &id)
                .with_context(|| format!("removing reingest marker for {id}"))?;
            println!("removed {id}");
        }
        removed += 1;
    }

    let verb = if dry_run { "prunable" } else { "pruned" };
    println!("{verb}: {removed}; kept (dataset still known to this node): {kept}");
    Ok(())
}

/// Write the override store to `output`, or to stdout when `output` is `None`.
///
/// # Errors
///
/// Returns an error when a loader directory is unreadable, when a store file is not valid
/// JSON, or when the output cannot be written.
pub fn export(config: &ServiceConfig, output: Option<&Path>) -> Result<()> {
    let root = config.service.override_dir_resolved();
    let mut stores = BTreeMap::new();
    let mut total = 0usize;
    for dir in override_store::loader_dirs(&root) {
        let entries = read_store(&dir)?;
        total += entries.len();
        stores.insert(store_key(&dir)?, entries);
    }
    // Lift records: the re-exposure justifications, captured so a DR restore brings them
    // back too (they have no other off-volume home). Not counted in `total` — that number
    // is in-force overrides, and a lift record records what is no longer in force.
    let history = read_history(&crate::lift_record::lifted_subdir(config))?;

    let bundle = Bundle {
        bundle_version: BUNDLE_VERSION,
        stores,
        history,
    };
    let mut json = serde_json::to_string_pretty(&bundle).context("cannot serialise the bundle")?;
    json.push('\n');

    match output {
        Some(path) => {
            // Atomic, durable and private (0600) like the store files it copies. This is
            // a disaster-recovery artifact, and a bare in-place write would truncate the
            // previous good bundle if the export were interrupted. The bundle also carries
            // governance reasons, so it inherits the store's file mode rather than the
            // operator's umask.
            gdi_node_standalone_core::util::write_durable_atomic_private(path, json.as_bytes())
                .with_context(|| format!("cannot write {}", path.display()))?;
            println!(
                "exported {} override(s) from {} to {}",
                total,
                root.display(),
                path.display()
            );
        }
        None => print!("{json}"),
    }
    Ok(())
}

/// One of the loader stores `override_store::loader_dirs` returns, as a closed set.
///
/// An enum rather than the `&str` directory name the bundle carries. A string match needs a
/// catch-all arm, and since the caller loops over the known stores, that arm would catch a
/// known store the match has forgotten, writing its entries with no body validation and no
/// compile error. As an enum it fails to compile instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoaderStore {
    /// `suppressions/` — dataset and channel withholds.
    Suppressions,
    /// `overlays/` — node-local metadata corrections.
    Overlays,
}

impl LoaderStore {
    /// Resolve a loader directory's name. `None` for a name this build does not read, which
    /// `import` rejects by name before it reaches any body check.
    fn from_key(key: &str) -> Option<Self> {
        match key {
            "suppressions" => Some(Self::Suppressions),
            "overlays" => Some(Self::Overlays),
            _ => None,
        }
    }

    /// The directory name, for messages.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Suppressions => "suppressions",
            Self::Overlays => "overlays",
        }
    }
}

/// Report a bundle entry whose body the node cannot apply as written. "Cannot apply" rather
/// than "would refuse", because only the overlay arm is refused at apply time.
///
/// Keyed on the store, because the two fail differently: a suppression that does not
/// deserialize is read fail-closed as `Hide` (so it over-withholds, quietly), while an
/// overlay that does not pass `validate_patch` is dropped at merge time yet still asserts
/// operator > source precedence — serving neither the correction nor the source metadata.
fn validate_entry_body(store: LoaderStore, file: &str, value: &serde_json::Value) -> Result<()> {
    match store {
        LoaderStore::Suppressions => {
            serde_json::from_value::<gdi_node_standalone_core::suppression::Suppression>(
                value.clone(),
            )
            .with_context(|| {
                format!(
                    "{}/{file} is not a valid suppression; the node would read it \
                         fail-closed as `hide` rather than applying what it says",
                    store.as_str()
                )
            })?;
        }
        LoaderStore::Overlays => {
            let overlay =
                serde_json::from_value::<gdi_node_standalone_core::model::MetadataOverlay>(
                    value.clone(),
                )
                .with_context(|| {
                    format!("{}/{file} is not a valid metadata overlay", store.as_str())
                })?;
            gdi_node_standalone_core::validate_pkg::validate_patch(&overlay).with_context(
                || {
                    format!(
                        "{}/{file} would be rejected by the node at apply time, and its \
                         presence would still block the source metadata, so the dataset \
                         would be served with neither",
                        store.as_str()
                    )
                },
            )?;
        }
    }
    Ok(())
}

/// What a bundle write produced, shared with the write closure so a mid-write failure still
/// reports what landed.
///
/// The audit line and the count run on both paths. A partial write with no record is the
/// failure the pre-flight structure exists to prevent, and an ENOSPC can still produce one
/// where validation no longer can.
#[derive(Default)]
struct WriteTally {
    /// Entries durably written.
    written: usize,
    /// Keys (`<store>/<file>`) of in-force entries this import replaced, capped at
    /// [`crate::audit::MAX_AUDITED_REPLACEMENTS`]. Never bodies: a suppression carries an
    /// operator `reason`, which is free text about a data subject.
    replaced: Vec<String>,
    /// How many were replaced in total, so a capped list is visibly capped.
    replaced_total: usize,
}

impl WriteTally {
    /// Record one entry that is now durably on disk, and whether it replaced an in-force
    /// one.
    ///
    /// The single place either counter moves, called only after the write returns `Ok`. Both
    /// facts land together or not at all, so a failed write cannot leave the audit line
    /// naming a take-down as replaced while the on-disk entry is untouched.
    fn note_written(&mut self, replaced_key: Option<String>) {
        self.written += 1;
        if let Some(key) = replaced_key {
            self.replaced_total += 1;
            if self.replaced.len() < crate::audit::MAX_AUDITED_REPLACEMENTS {
                self.replaced.push(key);
            }
        }
    }
}

/// Write every entry of `bundle` into its store directory, tallying replacements.
///
/// Split out of [`import`] for length. Pre-flight has already validated every body by the
/// time this runs, so the only failures here are I/O.
///
/// # Errors
///
/// Propagates a directory-create, serialise or write failure. The tally is still valid on
/// that path — it reports what landed before the failure.
fn write_bundle(
    known: &std::collections::BTreeMap<String, std::path::PathBuf>,
    bundle: &Bundle,
    tally: &mut WriteTally,
) -> Result<()> {
    for (name, dir) in known {
        let Some(entries) = bundle.stores.get(name) else {
            continue;
        };
        gdi_node_standalone_core::util::create_private_dir(dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        for (file, value) in entries {
            let mut json =
                serde_json::to_string_pretty(value).context("cannot serialise an entry")?;
            json.push('\n');
            let path = dir.join(file);
            // An overwrite of an in-force entry is reported. `--force`'s help says it
            // "never deletes, so it cannot lift a withhold", which holds only in the
            // narrowest sense: replacing a `remove` take-down, which evicts the local copy
            // and refuses re-ingest, with a stale `hide` leaves the dataset withheld but
            // undoes the erasure. Without the tally below that would be unnamed among an
            // aggregate count.
            let replaced = note_overwrite_if_weaker(&path, value).then(|| format!("{name}/{file}"));
            gdi_node_standalone_core::util::write_durable_atomic_private(&path, json.as_bytes())
                .with_context(|| format!("cannot write {}", path.display()))?;
            // Tallied only once the entry is durably on disk — see `note_written`.
            tally.note_written(replaced);
        }
    }
    Ok(())
}

/// Note every import overwrite of an in-force entry, warning when it demonstrably weakens
/// one.
///
/// The warning is narrow by construction: the only relation this recognises as weakening is
/// a suppression's `remove` becoming a non-`remove`. Everything else, including an overlay,
/// which carries no `mode` at all, takes the generic `info` arm, so an overlay replacement
/// never produces a "weaker" signal.
///
/// Best-effort and never fatal: `--force` is documented as overwriting, and the operator
/// asked for it. What must not happen is a replacement nobody can see, since an aggregate
/// count with no names cannot distinguish a `remove` becoming a `hide`, which undoes an
/// eviction and a re-ingest refusal, from a no-op re-import.
///
/// Returns `true` when an entry that was in force has been replaced by something different,
/// so the caller can name it in the durable audit record. `false` for a create, and for a
/// byte-identical re-import, which changes nothing and is not worth recording.
fn note_overwrite_if_weaker(path: &std::path::Path, incoming: &serde_json::Value) -> bool {
    let existing = match std::fs::read(path) {
        Ok(bytes) => bytes,
        // An absent file is the only create case. Every other error (EACCES, EISDIR, EIO
        // on a network volume) is a file that is present and in force. Taking the create
        // branch for those would overwrite an unreadable `remove` take-down with a weaker
        // `hide` and no warning, leaving the two cases where the in-force state is unknown
        // as the two with no signal.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "import is overwriting an override it could not read, so whether this \
                 weakens or lifts a withhold in force is unknown. If it was a `remove` \
                 take-down, this reverses it"
            );
            return true;
        }
    };
    let existing = match serde_json::from_slice::<serde_json::Value>(&existing) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "import is overwriting an override that does not parse; the node reads such \
                 a suppression fail-closed as `hide`, so a withhold is in force here and \
                 this replaces it with something unknown"
            );
            return true;
        }
    };
    if existing == *incoming {
        return false;
    }
    let mode_of = |v: &serde_json::Value| v.get("mode").and_then(|m| m.as_str()).map(str::to_owned);
    match (mode_of(&existing), mode_of(incoming)) {
        (Some(before), Some(after)) if before == "remove" && after != "remove" => {
            tracing::warn!(
                path = %path.display(),
                before = %before,
                after = %after,
                "import is replacing a `remove` take-down with a weaker mode: the local copy \
                 will no longer be erased and re-ingest will no longer be refused. If that \
                 take-down recorded a consent withdrawal, this reverses it"
            );
        }
        _ => {
            tracing::info!(path = %path.display(), "import is overwriting an existing override");
        }
    }
    true
}

/// Validate every entry body in the bundle, returning the ones the node would refuse.
///
/// Split out of [`import`] so the whole bundle is checked before a single file is written.
/// Validating per entry inside the write loop instead would let a bad entry N leave entries
/// 1..N-1 durably on disk with no record, and the retry would then be refused by the
/// "already populated" guard unless the operator reached for `--force` to clean up the
/// tool's own partial write.
///
/// Returns `(store/file, reason)` rather than erroring on the first one: `import` installs
/// them anyway and reports them together. See [`import`] for why installing beats refusing.
///
/// # Errors
///
/// Only when a loader directory has no known [`LoaderStore`] kind — unreachable via
/// `import`, which rejects unknown store names first, and a refusal rather than a silent
/// skip if it ever becomes reachable.
fn preflight_entry_bodies(
    known: &BTreeMap<String, std::path::PathBuf>,
    bundle: &Bundle,
) -> Result<Vec<(String, String)>> {
    let mut suspect = Vec::new();
    for (name, dir) in known {
        let Some(entries) = bundle.stores.get(name) else {
            continue;
        };
        let Some(store) = LoaderStore::from_key(name) else {
            bail!(
                "loader directory {} has no known store kind; refusing to import bodies this \
                 build cannot validate",
                dir.display()
            );
        };
        for (file, value) in entries {
            if let Err(e) = validate_entry_body(store, file, value) {
                suspect.push((format!("{name}/{file}"), format!("{e:#}")));
            }
        }
    }
    Ok(suspect)
}

/// Rewrite the lift-record `history` from a bundle into `<override_dir>/lifted/`.
///
/// Best-effort with a per-file warning, as `lift_record` writes them in the first place.
/// These are audit records that make nothing in-force, since the loaders and `is_populated`
/// ignore `lifted/`, so a failed history write must never fail the restore of the overrides
/// that do govern disclosure. Returns how many records landed.
fn restore_history(config: &ServiceConfig, history: &BTreeMap<String, serde_json::Value>) -> usize {
    if history.is_empty() {
        return 0;
    }
    let lifted = crate::lift_record::lifted_subdir(config);
    if let Err(e) = gdi_node_standalone_core::util::create_private_dir(&lifted) {
        warn!(dir = %lifted.display(), error = %e, "could not create lifted/; lift-record history not restored");
        return 0;
    }
    let mut written = 0usize;
    for (name, value) in history {
        let path = lifted.join(name);
        let bytes = match serde_json::to_vec_pretty(value) {
            Ok(b) => b,
            Err(e) => {
                warn!(entry = %name, error = %e, "skipping an unserialisable lift record");
                continue;
            }
        };
        match gdi_node_standalone_core::util::write_durable_atomic_private(&path, &bytes) {
            Ok(()) => written += 1,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "could not restore a lift record; the override restore is unaffected");
            }
        }
    }
    written
}

/// Restore an override store from a bundle written by [`export`].
///
/// Refuses by default when the target store already holds overrides: the DR case is
/// restoring into a node believed to have lost its state, and silently merging into a
/// populated store would leave an operator unsure which withholds are actually in force.
/// `force` overwrites same-named entries and leaves any extra ones in place — it is a
/// union, never a delete, so `import` can add to a store but can never remove a withhold.
///
/// A body that would be refused at apply time does not abort the restore: it is installed,
/// named on stdout, and the command exits non-zero. Leaving it out is the disclosure
/// direction, since an absent suppression serves the dataset and an absent overlay
/// republishes the metadata it redacted, whereas the node reads a malformed suppression
/// fail-closed as `hide` and a malformed overlay keeps its precedence claim.
///
/// # Errors
///
/// Returns an error when the bundle is unreadable, carries an unknown `bundleVersion` or
/// an unknown store, contains an entry name that is not a plain `*.json` file, when the
/// target store is already populated and `force` is not set, when a write fails (the audit
/// line and the count are still emitted first, so a partial import is never silent), or —
/// after everything has been installed — when any entry body was malformed.
pub fn import(config: &ServiceConfig, input: &Path, force: bool) -> Result<()> {
    let text = std::fs::read_to_string(input)
        .with_context(|| format!("cannot read bundle {}", input.display()))?;
    let bundle: Bundle = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a valid override bundle", input.display()))?;

    // Accept v1 (no history) and v2 (history-bearing): a v1 bundle predates lift-record
    // backup and simply restores no history, which is exactly right for it. Anything newer
    // is a format this build does not know.
    if bundle.bundle_version == 0 || bundle.bundle_version > BUNDLE_VERSION {
        bail!(
            "bundle {} declares bundleVersion {}, this build understands 1..={}. Refusing to \
             guess at a format it does not know",
            input.display(),
            bundle.bundle_version,
            BUNDLE_VERSION
        );
    }

    let root = config.service.override_dir_resolved();
    let dirs = override_store::loader_dirs(&root);

    // Every store in the bundle must map to a loader directory this build reads. A bundle
    // from a node with a store this one does not know would otherwise be imported minus
    // that store, reporting success while dropping overrides on the floor.
    let mut known = BTreeMap::new();
    for dir in &dirs {
        known.insert(store_key(dir)?, dir.clone());
    }
    for name in bundle.stores.keys() {
        if !known.contains_key(name) {
            bail!(
                "bundle contains store {name:?}, which this build does not read (known: \
                 {:?}). Importing would silently discard it",
                known.keys().collect::<Vec<_>>()
            );
        }
    }

    for name in bundle.stores.keys() {
        for entry in bundle.stores[name].keys() {
            validate_entry_name(entry)?;
        }
    }
    for entry in bundle.history.keys() {
        validate_entry_name(entry)?;
    }

    if !force && override_store::is_populated(&root) {
        bail!(
            "the override store at {} already holds overrides. Importing into it would \
             leave the in-force set ambiguous. Re-run with --force to overwrite same-named \
             entries (extras are kept; nothing is ever deleted)",
            root.display()
        );
    }

    // Check every body before writing anything, then install all of them.
    //
    // Validation runs before the write loop, not inside it: validating mid-loop would let a
    // bad entry N leave entries 1..N-1 durably on disk with no audit record, and the retry is
    // then refused by the "already populated" guard above unless the operator reaches for
    // `--force` to clean up the tool's own partial write. `correct_cmd` validates before
    // writing for the same reason.
    //
    // A body that fails validation is still installed, named, and the command exits non-zero.
    // In the recovery case this verb exists for, an absent entry is the disclosure direction
    // for both stores: a missing suppression serves the dataset, and a missing overlay
    // republishes the metadata the operator was redacting. A present-but-malformed entry is
    // safer, because the node reads a malformed suppression fail-closed as `hide` and a
    // malformed overlay keeps its precedence claim. So report loudly and exit non-zero, but
    // never let this command be the reason a withhold is missing.
    let suspect = preflight_entry_bodies(&known, &bundle)?;

    // Through the shared first-override advisory, like every other store-populating verb.
    // `import` is the command most likely to take a store from empty to populated, and
    // `docs/operating.md` §17 tells the operator to set `require_override_store` afterwards.
    //
    // `tally` is shared with the closure so a mid-write I/O failure still reports what
    // landed (see `WriteTally`).
    let mut tally = WriteTally::default();
    let outcome = crate::override_advice::with_first_override_advice(config, || {
        write_bundle(&known, &bundle, &mut tally)
    });
    let WriteTally {
        written,
        replaced,
        replaced_total,
    } = tally;

    crate::audit::overrides_imported(
        &config.audit,
        &root.display().to_string(),
        written,
        force,
        &replaced,
        replaced_total,
    );
    println!(
        "imported {} override(s) into {}; the node picks them up on its next reload \
         (SIGUSR1, or the override reconcile timer), and a stopped node loads them at boot",
        written,
        root.display()
    );
    // Everything that reports what landed runs before the write error propagates: the count,
    // the audit line, and this list. A malformed entry that was installed is read fail-closed
    // as `hide`, so an operator who learns only about the ENOSPC is left with entries on disk
    // they were never told about.
    if !suspect.is_empty() {
        for (entry, why) in &suspect {
            println!("  ! {entry}: {why}");
        }
    }
    // Restore the lift-record history (audit records — best-effort, nothing in-force).
    let history_written = restore_history(config, &bundle.history);
    if history_written > 0 {
        println!(
            "restored {history_written} lift record(s) into {}",
            crate::lift_record::lifted_subdir(config).display()
        );
    }

    // The used marker re-derives from what landed on disk, before `outcome?` propagates a
    // write error, so even a partial import (ENOSPC mid-loop) marks the entries that did
    // install.
    crate::override_marker::sync(config);
    outcome?;

    if !suspect.is_empty() {
        bail!(
            "{} of {} imported entr{} malformed. They were installed rather than skipped: \
             a malformed suppression is read fail-closed as `hide`, and a malformed overlay \
             keeps its operator-over-source precedence claim, so leaving either out would \
             have served the dataset or republished the metadata it was redacting. Fix them \
             in the source bundle and re-import with --force",
            suspect.len(),
            written,
            if suspect.len() == 1 {
                "y is"
            } else {
                "ies are"
            }
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    fn config_with_override_dir(dir: &Path) -> ServiceConfig {
        let toml = format!(
            r#"
[service]
base_url = "https://n.example.org/"
data_dir = "/var/lib/gdi/datasets"
override_dir = "{}"

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
            dir.display()
        );
        ServiceConfig::from_toml_str(&toml).unwrap()
    }

    // -----------------------------------------------------------------------
    // init: create when absent, attest (--yes) when the used marker stands
    // -----------------------------------------------------------------------

    /// A config whose `data_dir` exists (so the marker can live there) and whose override
    /// root does not (the never-used shape).
    fn init_rig() -> (ServiceConfig, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = config_with_dirs(&tmp.path().join("data"), &tmp.path().join("overrides"));
        (cfg, tmp)
    }

    /// Only the marker's presence is consulted, so a bare file is the marker.
    fn plant_marker(cfg: &ServiceConfig) {
        std::fs::write(crate::override_marker::marker_path(cfg), b"{}\n").unwrap();
    }

    #[test]
    fn init_creates_the_store_when_absent_and_never_used() {
        let (cfg, _tmp) = init_rig();
        let root = cfg.service.override_dir_resolved();
        init(&cfg, false).expect("a never-used node needs no --yes");
        assert!(override_store::is_present(&root), "both loader dirs exist");
        assert!(
            !crate::override_marker::marker_path(&cfg).exists(),
            "nothing to attest, nothing cleared"
        );
        crate::override_marker::sync_and_assert(&cfg, true).expect("boots");
    }

    #[test]
    fn init_refuses_an_absent_store_under_the_marker_without_yes_and_creates_nothing() {
        // The lost-volume shape: the override root is gone and the data volume remembers
        // that overrides existed. Creating an empty store here would leave the marker to
        // fail the next boot, taking two runs to reach a clean boot without ever asking
        // whether the operator meant it.
        let (cfg, _tmp) = init_rig();
        let root = cfg.service.override_dir_resolved();
        plant_marker(&cfg);

        let err = init(&cfg, false).expect_err("must refuse without --yes");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("overrides import") && msg.contains("--yes"),
            "the refusal names both the recovery and the override: {msg}"
        );
        assert!(!root.exists(), "a refusal creates nothing");
        assert!(
            crate::override_marker::marker_path(&cfg).exists(),
            "a refusal clears nothing"
        );
    }

    #[test]
    fn init_with_yes_on_an_absent_store_under_the_marker_creates_and_attests_in_one_run() {
        let (cfg, _tmp) = init_rig();
        let root = cfg.service.override_dir_resolved();
        plant_marker(&cfg);

        init(&cfg, true).expect("--yes creates and attests");
        assert!(override_store::is_present(&root));
        assert!(
            !crate::override_marker::marker_path(&cfg).exists(),
            "one run leaves a booting node: the marker is cleared"
        );
        crate::override_marker::sync_and_assert(&cfg, true).expect("boots after one init");
    }

    #[test]
    fn init_refuses_a_present_and_empty_store_under_the_marker_without_yes() {
        // The structure-only restore shape: tree intact, files gone, marker standing.
        let (cfg, _tmp) = init_rig();
        let root = cfg.service.override_dir_resolved();
        override_store::create_store_dir(
            &gdi_node_standalone_core::suppression::suppressions_subdir(&root),
        )
        .unwrap();
        plant_marker(&cfg);
        crate::override_marker::sync_and_assert(&cfg, true).expect_err("sanity: boot refuses");

        let err = init(&cfg, false).expect_err("attesting needs --yes");
        assert!(format!("{err:#}").contains("--yes"), "{err:#}");
        assert!(
            crate::override_marker::marker_path(&cfg).exists(),
            "a refusal clears nothing"
        );
        crate::override_marker::sync_and_assert(&cfg, true).expect_err("still refuses");

        init(&cfg, true).expect("--yes attests");
        assert!(!crate::override_marker::marker_path(&cfg).exists());
        crate::override_marker::sync_and_assert(&cfg, true).expect("boots");
    }

    /// The init-container contract: running `overrides init` on every boot must be safe.
    ///
    /// `deploy/kubernetes` runs it as an init container because boot creates nothing, so a
    /// node that sets `require_override_store` before it has ever recorded an override
    /// cannot start at all on a fresh volume. An init container runs on every start, and a
    /// non-zero exit there is a pod that never comes up, so "no-op on an intact store" is
    /// the property that design rests on.
    #[test]
    fn init_is_a_no_op_the_second_time_so_it_can_run_on_every_boot() {
        let (cfg, _tmp) = init_rig();
        let root = cfg.service.override_dir_resolved();
        init(&cfg, false).expect("first run creates the store");
        init(&cfg, false).expect("second run is a no-op, not an error");
        init(&cfg, false).expect("and stays one");
        assert!(override_store::is_present(&root), "the store still stands");
        assert!(
            !crate::override_marker::marker_path(&cfg).exists(),
            "a no-op writes no marker"
        );
        crate::override_marker::sync_and_assert(&cfg, true).expect("boots");
    }

    #[test]
    fn init_is_a_no_op_on_a_populated_store_even_with_yes() {
        let (cfg, _tmp) = init_rig();
        let root = cfg.service.override_dir_resolved();
        gdi_node_standalone_core::suppression::write_file(
            &gdi_node_standalone_core::suppression::suppressions_subdir(&root),
            "GDI-EE-UTARTU-20260409143052837",
            &gdi_node_standalone_core::suppression::Suppression {
                mode: gdi_node_standalone_core::suppression::SuppressMode::Remove,
                reason: "r".to_owned(),
                at: String::new(),
            },
        )
        .unwrap();
        crate::override_marker::sync(&cfg);

        // A populated store is the steady state of a node that has ever suppressed
        // anything, and the marker stands there too, since it is cleared only when the last
        // withhold is lifted. This is the shape the init container meets on every restart of
        // a working node: it must succeed and must touch nothing.
        init(&cfg, true).expect("a populated store has nothing to initialise — no-op");
        assert!(
            crate::override_marker::marker_path(&cfg).exists(),
            "--yes on a populated store must not clear the marker"
        );
        assert!(
            override_store::is_populated(&root),
            "and must not touch the store"
        );
    }

    const MARKER_ID: &str = "GDI-EE-UTARTU-20260409143052837";

    /// A config whose `data_dir` and `override_dir` both really exist, so the prune path
    /// can tell a known dataset from an unknown one.
    fn config_with_dirs(data_dir: &Path, override_dir: &Path) -> ServiceConfig {
        std::fs::create_dir_all(data_dir).unwrap();
        let toml = format!(
            r#"
[service]
base_url = "https://n.example.org/"
data_dir = "{}"
override_dir = "{}"

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
            data_dir.display(),
            override_dir.display()
        );
        ServiceConfig::from_toml_str(&toml).unwrap()
    }

    fn marker_exists(override_dir: &Path, id: &str) -> bool {
        reingest_request::requests_subdir(override_dir)
            .join(format!("{id}.json"))
            .exists()
    }

    #[test]
    fn prune_reingest_removes_a_marker_for_a_dataset_the_node_has_no_trace_of() {
        let tmp = tempfile::tempdir().unwrap();
        let (data, over) = (tmp.path().join("data"), tmp.path().join("over"));
        let config = config_with_dirs(&data, &over);
        reingest_request::write_marker(&reingest_request::requests_subdir(&over), MARKER_ID)
            .unwrap();

        prune_reingest(&config, false, false).unwrap();

        assert!(
            !marker_exists(&over, MARKER_ID),
            "a marker for a dataset that no longer exists is dead weight and reads like \
             pending work during an incident"
        );
    }

    #[test]
    fn prune_reingest_keeps_a_marker_for_a_dataset_that_still_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let (data, over) = (tmp.path().join("data"), tmp.path().join("over"));
        let config = config_with_dirs(&data, &over);
        std::fs::create_dir_all(data.join(MARKER_ID)).unwrap();
        reingest_request::write_marker(&reingest_request::requests_subdir(&over), MARKER_ID)
            .unwrap();

        prune_reingest(&config, false, false).unwrap();

        assert!(
            marker_exists(&over, MARKER_ID),
            "another replica may not have observed this request yet; withdrawing it here \
             would silently deny it"
        );
    }

    #[test]
    fn prune_reingest_all_withdraws_even_a_live_request() {
        let tmp = tempfile::tempdir().unwrap();
        let (data, over) = (tmp.path().join("data"), tmp.path().join("over"));
        let config = config_with_dirs(&data, &over);
        std::fs::create_dir_all(data.join(MARKER_ID)).unwrap();
        reingest_request::write_marker(&reingest_request::requests_subdir(&over), MARKER_ID)
            .unwrap();

        prune_reingest(&config, true, false).unwrap();

        assert!(!marker_exists(&over, MARKER_ID), "--all is unconditional");
    }

    #[test]
    fn prune_reingest_dry_run_changes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (data, over) = (tmp.path().join("data"), tmp.path().join("over"));
        let config = config_with_dirs(&data, &over);
        reingest_request::write_marker(&reingest_request::requests_subdir(&over), MARKER_ID)
            .unwrap();

        prune_reingest(&config, true, true).unwrap();

        assert!(
            marker_exists(&over, MARKER_ID),
            "--dry-run must report without removing"
        );
    }

    /// A store with one suppression and one overlay.
    fn seed(root: &Path) {
        for dir in override_store::loader_dirs(root) {
            std::fs::create_dir_all(&dir).unwrap();
            let name = dir.file_name().unwrap().to_str().unwrap().to_owned();
            // Real bodies, not placeholders. `import` validates each entry against the type
            // its store loads, so a fixture the node would refuse makes the round-trip test
            // pass on data no node accepts.
            let body = if name == "suppressions" {
                r#"{"mode":"hide","reason":"seeded","at":"2026-08-05T00:00:00Z"}"#.to_owned()
            } else {
                r#"{"title":{"en":"seeded"}}"#.to_owned()
            };
            // A name the loader admits: `is_populated` counts exactly what the loaders
            // would load, so a store seeded under a junk name is not "populated".
            std::fs::write(dir.join(format!("{SEEDED_ID}.json")), body).unwrap();
        }
    }

    /// The valid dataset id [`seed`] writes under, in both loader directories.
    const SEEDED_ID: &str = "GDI-EE-UTARTU-20260409143052837";

    fn entries(root: &Path) -> Vec<String> {
        let mut out = vec![];
        for dir in override_store::loader_dirs(root) {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    out.push(e.file_name().to_string_lossy().into_owned());
                }
            }
        }
        out.sort();
        out
    }

    fn lifted_files(
        root: &std::path::Path,
    ) -> std::collections::BTreeMap<String, serde_json::Value> {
        let dir = root.join("lifted");
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return std::collections::BTreeMap::new();
        };
        rd.filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    serde_json::from_str(&std::fs::read_to_string(e.path()).unwrap()).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn export_v2_carries_lift_records_and_import_restores_them_without_making_them_in_force() {
        use gdi_node_standalone_core::suppression::{SuppressMode, Suppression};
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let bundle = src.path().join("b.json");
        seed(src.path());
        // A lifted withhold leaves a lift record under lifted/.
        let lifted = Suppression {
            mode: SuppressMode::Hide,
            reason: "the withhold reason".to_owned(),
            at: "2026-08-01T00:00:00Z".to_owned(),
        };
        crate::lift_record::record_dataset_lift(
            &config_with_override_dir(src.path()),
            "GDI-EE-UTARTU-20260409143052837",
            &lifted,
            "erasure request withdrawn",
        );
        let src_history = lifted_files(src.path());
        assert_eq!(src_history.len(), 1, "the lift produced one record");

        export(&config_with_override_dir(src.path()), Some(&bundle)).unwrap();
        let text = std::fs::read_to_string(&bundle).unwrap();
        assert!(
            text.contains("\"bundleVersion\": 2"),
            "history-bearing bundle is v2: {text}"
        );
        assert!(
            text.contains("\"history\""),
            "the bundle carries a history key"
        );

        import(&config_with_override_dir(dst.path()), &bundle, false).unwrap();
        assert_eq!(
            lifted_files(dst.path()),
            src_history,
            "the lift records round-trip value-for-value (JSON re-serialises with sorted keys)"
        );
        // The restored history must not count as an active override: a store whose only
        // content is `lifted/` records is still empty for `is_populated`, so a
        // `require_override_store` node does not refuse to boot over its own audit trail.
        let dst2 = tempfile::tempdir().unwrap();
        {
            let cfg = config_with_override_dir(dst2.path());
            crate::lift_record::record_dataset_lift(
                &cfg,
                "GDI-EE-UTARTU-20260409143052837",
                &lifted,
                "r",
            );
        }
        assert!(
            !override_store::is_populated(dst2.path()),
            "a lifted/-only store is not populated"
        );
    }

    #[test]
    fn a_v1_bundle_still_imports_and_restores_no_history() {
        let dst = tempfile::tempdir().unwrap();
        let bundle = dst.path().join("v1.json");
        // A hand-written v1 bundle: no history key at all.
        std::fs::write(
            &bundle,
            r#"{"bundleVersion":1,"stores":{"suppressions":{},"overlays":{}}}"#,
        )
        .unwrap();
        import(&config_with_override_dir(dst.path()), &bundle, false).unwrap();
        assert!(
            lifted_files(dst.path()).is_empty(),
            "v1 restores no history"
        );
    }

    #[test]
    fn export_then_import_into_an_empty_store_round_trips() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let bundle = src.path().join("b.json");
        seed(src.path());

        export(&config_with_override_dir(src.path()), Some(&bundle)).unwrap();
        // The store the loaders read must exist for import's own dirs; import creates them.
        import(&config_with_override_dir(dst.path()), &bundle, false).unwrap();

        assert_eq!(
            entries(src.path()),
            entries(dst.path()),
            "a round trip must reproduce exactly the entries the loaders read"
        );
    }

    #[test]
    fn the_bundle_is_readable_json_with_a_version() {
        let src = tempfile::tempdir().unwrap();
        let bundle = src.path().join("b.json");
        seed(src.path());
        export(&config_with_override_dir(src.path()), Some(&bundle)).unwrap();

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&bundle).unwrap()).unwrap();
        assert_eq!(v["bundleVersion"], 2);
        // Entries are stored parsed, not as escaped strings, which is the point of
        // choosing JSON over a tar. If this becomes a string the artifact stops being
        // diffable.
        assert_eq!(
            v["stores"]["suppressions"][format!("{SEEDED_ID}.json")]["mode"],
            "hide"
        );
    }

    #[test]
    fn import_refuses_a_populated_store_without_force() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let bundle = src.path().join("b.json");
        seed(src.path());
        seed(dst.path());
        export(&config_with_override_dir(src.path()), Some(&bundle)).unwrap();

        let err = import(&config_with_override_dir(dst.path()), &bundle, false).unwrap_err();
        assert!(
            err.to_string().contains("already holds overrides"),
            "expected a refusal naming the populated store, got: {err}"
        );
    }

    /// A replacement of an in-force entry is reported, so the audit line can name it.
    ///
    /// `note_overwrite_if_weaker` returns the verdict rather than only warning through
    /// `tracing`, so `overrides_imported` can record more than an aggregate count. A durable
    /// stream carrying only counts cannot answer "which withholds did this import replace",
    /// which makes a `remove` take-down quietly becoming a `hide` (reversing a
    /// consent-withdrawal erasure) indistinguishable from a no-op re-import.
    ///
    /// The three answers that matter: a create is not a replacement, a byte-identical
    /// re-import is not a replacement, and anything else is.
    #[test]
    fn an_overwrite_of_an_in_force_entry_is_reported_to_the_caller() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("GDI-EE-UTARTU-1.json");
        let hide = serde_json::json!({"mode": "hide", "reason": "r"});
        let remove = serde_json::json!({"mode": "remove", "reason": "r"});

        // Absent: a create, not a replacement.
        assert!(
            !note_overwrite_if_weaker(&path, &hide),
            "a create must not be recorded as replacing an in-force entry"
        );

        std::fs::write(&path, serde_json::to_string(&remove).unwrap()).unwrap();
        // Byte-identical: nothing changed, so nothing to record.
        assert!(
            !note_overwrite_if_weaker(&path, &remove),
            "a byte-identical re-import replaces nothing"
        );
        // A real replacement, and the one that matters most: `remove` -> `hide`.
        assert!(
            note_overwrite_if_weaker(&path, &hide),
            "replacing an in-force `remove` with a weaker mode must be reported"
        );

        // An unreadable entry is a replacement too: it is present and in force, and the
        // two cases where the in-force state is unknown most need naming.
        let unreadable = dir.path().join("unreadable.json");
        std::fs::write(&unreadable, b"{ not json").unwrap();
        assert!(
            note_overwrite_if_weaker(&unreadable, &hide),
            "overwriting an entry that does not parse must be reported: the node reads such \
             a suppression fail-closed as `hide`, so a withhold is in force there"
        );
    }

    #[test]
    fn import_with_force_overwrites_but_never_deletes() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let bundle = src.path().join("b.json");
        seed(src.path());
        seed(dst.path());
        // An extra withhold absent from the bundle must survive: import is a union, so
        // restoring a stale backup can never silently lift a withhold in force today.
        let extra = override_store::loader_dirs(dst.path())[0].join("keep-me.json");
        std::fs::write(
            &extra,
            r#"{"mode":"hide","reason":"extra","at":"2026-08-05T00:00:00Z"}"#,
        )
        .unwrap();

        export(&config_with_override_dir(src.path()), Some(&bundle)).unwrap();
        import(&config_with_override_dir(dst.path()), &bundle, true).unwrap();

        assert!(
            extra.is_file(),
            "--force must not delete an entry absent from the bundle"
        );
    }

    /// A malformed body is installed, named, and the command exits non-zero, and the
    /// entries around it land too.
    ///
    /// Validation runs before the write loop, so a bad entry cannot abort mid-restore and
    /// leave earlier entries durably on disk with no audit line and no output saying so, a
    /// state the "already populated" guard would then refuse to retry without `--force`.
    ///
    /// Installing the bad entry rather than refusing it is the safer half. In the recovery
    /// case this verb exists for, an absent suppression serves the dataset and an absent
    /// overlay republishes the metadata it redacted, while the node reads a malformed
    /// suppression fail-closed as `hide`. Refusing would be the disclosure direction.
    #[test]
    fn a_malformed_entry_is_installed_and_reported_not_silently_skipped() {
        let dst = tempfile::tempdir().unwrap();
        let bundle = dst.path().join("b.json");
        // `aaa` sorts before `zzz`, so the bad entry is not last: an abort would drop `zzz`.
        std::fs::write(
            &bundle,
            r#"{"bundleVersion":1,"stores":{"suppressions":{
                 "aaa-bad.json":{"mode":"not-a-mode","reason":"x","at":"2026-08-05T00:00:00Z"},
                 "zzz-good.json":{"mode":"hide","reason":"ok","at":"2026-08-05T00:00:00Z"}}}}"#,
        )
        .unwrap();

        let err = import(&config_with_override_dir(dst.path()), &bundle, false)
            .expect_err("a malformed body must exit non-zero");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("malformed"),
            "the failure must say what was wrong: {msg}"
        );

        let landed = entries(dst.path());
        assert!(
            landed.contains(&"zzz-good.json".to_owned()),
            "an entry after the malformed one must still be installed: {landed:?}"
        );
        assert!(
            landed.contains(&"aaa-bad.json".to_owned()),
            "and the malformed one is installed too; absent is the disclosure direction, \
             present is read fail-closed as `hide`: {landed:?}"
        );
    }

    /// The overwrite warning's subject: a `remove` take-down replaced by a weaker `hide`.
    /// The `--force` test seeds source and destination byte-identically, so its equality
    /// early-out fires before `mode_of` is reached; only a differing `remove` fixture
    /// exercises the warning.
    #[test]
    fn importing_a_hide_over_an_in_force_remove_still_installs_and_is_visible() {
        let dst = tempfile::tempdir().unwrap();
        let sup = override_store::loader_dirs(dst.path())[0].clone();
        std::fs::create_dir_all(&sup).unwrap();
        let path = sup.join("GOE-EE-UTARTU-1.json");
        std::fs::write(
            &path,
            r#"{"mode":"remove","reason":"consent withdrawn","at":"2026-08-05T00:00:00Z"}"#,
        )
        .unwrap();

        let bundle = dst.path().join("b.json");
        std::fs::write(
            &bundle,
            r#"{"bundleVersion":1,"stores":{"suppressions":{
                 "GOE-EE-UTARTU-1.json":{"mode":"hide","reason":"stale backup","at":"2026-08-01T00:00:00Z"}}}}"#,
        )
        .unwrap();

        import(&config_with_override_dir(dst.path()), &bundle, true).unwrap();

        let after: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            after.get("mode").and_then(serde_json::Value::as_str),
            Some("hide"),
            "--force overwrites, as documented; the point is that it is not silent"
        );
    }

    #[test]
    fn a_bundle_entry_cannot_escape_the_store() {
        let dst = tempfile::tempdir().unwrap();
        let bundle = dst.path().join("evil.json");
        std::fs::write(
            &bundle,
            r#"{"bundleVersion":1,"stores":{"suppressions":{"../../pwned.json":{"x":1}}}}"#,
        )
        .unwrap();

        let err = import(&config_with_override_dir(dst.path()), &bundle, true).unwrap_err();
        assert!(
            err.to_string().contains("outside the override store"),
            "path traversal must be refused, got: {err}"
        );
        assert!(!dst.path().join("../../pwned.json").exists());
    }

    #[test]
    fn an_unknown_bundle_version_is_refused() {
        let dst = tempfile::tempdir().unwrap();
        let bundle = dst.path().join("b.json");
        std::fs::write(&bundle, r#"{"bundleVersion":99,"stores":{}}"#).unwrap();
        let err = import(&config_with_override_dir(dst.path()), &bundle, true).unwrap_err();
        assert!(err.to_string().contains("bundleVersion 99"), "got: {err}");
    }

    #[test]
    fn a_store_this_build_does_not_read_is_refused_not_dropped() {
        let dst = tempfile::tempdir().unwrap();
        let bundle = dst.path().join("b.json");
        std::fs::write(
            &bundle,
            r#"{"bundleVersion":1,"stores":{"suppressions":{},"future_store":{"a.json":{}}}}"#,
        )
        .unwrap();
        let err = import(&config_with_override_dir(dst.path()), &bundle, true).unwrap_err();
        assert!(
            err.to_string().contains("future_store"),
            "importing minus an unknown store would silently discard overrides, got: {err}"
        );
    }

    #[test]
    fn export_fails_loudly_on_a_corrupt_store_file() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path());
        let bad = override_store::loader_dirs(src.path())[0].join("broken.json");
        std::fs::write(&bad, "{not json").unwrap();

        let err = export(&config_with_override_dir(src.path()), None).unwrap_err();
        assert!(
            format!("{err:#}").contains("broken.json"),
            "the failing file must be named, got: {err:#}"
        );
    }

    #[test]
    fn export_fails_rather_than_emitting_an_empty_bundle_for_an_absent_store() {
        let src = tempfile::tempdir().unwrap();
        // No seed: the loader directories do not exist. An empty bundle here would be
        // indistinguishable from a successful backup of a destroyed store.
        let err = export(&config_with_override_dir(src.path()), None).unwrap_err();
        assert!(
            format!("{err:#}").contains("cannot read override store directory"),
            "got: {err:#}"
        );
    }

    /// A node that has recorded a suppression but never an overlay must still export.
    ///
    /// `read_store` treats an absent directory as an error, so a store where only
    /// `suppressions/` had been created would refuse the whole backup. On the default
    /// `require_override_store = false` posture, where `ensure_present` is a no-op, that is
    /// the state of every node the moment it first hides a dataset.
    ///
    /// `override_store::create_store_dir` materialises both directories on the first write,
    /// rather than export tolerating an absent one. Tolerating it would re-open the
    /// silent-withhold-lifting hole the strictness closes, which the test above pins.
    #[test]
    fn export_succeeds_with_a_suppression_and_no_overlay_yet() {
        let root = tempfile::tempdir().unwrap();
        let suppressions = gdi_node_standalone_core::suppression::suppressions_subdir(root.path());
        let overlays = gdi_node_standalone_core::overlay_override::overlays_subdir(root.path());

        // The real write path, exactly as `dataset hide` reaches it.
        gdi_node_standalone_core::suppression::write_file(
            &suppressions,
            "GDI-EE-UTARTU-20260409143052837",
            &gdi_node_standalone_core::suppression::Suppression {
                mode: gdi_node_standalone_core::suppression::SuppressMode::Hide,
                reason: "consent withdrawn".to_owned(),
                at: "2026-08-02T00:00:00Z".to_owned(),
            },
        )
        .unwrap();

        assert!(
            overlays.is_dir(),
            "the first suppression must materialise the sibling `overlays/` too, or the \
             store is unexportable until an unrelated `dataset correct` happens to run"
        );

        let out = root.path().join("bundle.json");
        export(&config_with_override_dir(root.path()), Some(&out)).unwrap();

        let bundle: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(
            bundle["stores"]["suppressions"].as_object().unwrap().len(),
            1
        );
        assert_eq!(
            bundle["stores"]["overlays"].as_object().unwrap().len(),
            0,
            "the untouched store must round-trip as an empty map, not be missing"
        );
    }

    /// A failed write must not leave the entry counted as replaced.
    ///
    /// The audit line answers "which in-force withholds did this import replace". Counting
    /// before the write would let an ENOSPC produce a durable record naming a `remove`
    /// take-down as replaced while the on-disk entry was untouched, the inverse of the truth
    /// in the one stream that survives a restart.
    ///
    /// Asserted in both directions: the same bundle written to a writable store does record
    /// the replacement, so this cannot pass by never tallying at all.
    #[cfg(unix)]
    #[test]
    fn a_failed_write_tallies_neither_the_entry_nor_its_replacement() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let dir = gdi_node_standalone_core::suppression::suppressions_subdir(root.path());
        std::fs::create_dir_all(&dir).unwrap();

        let id = "GDI-EE-UTARTU-20260409143052837";
        // An in-force `remove` take-down: the strongest entry, and the one whose silent
        // replacement the audit event exists to name.
        gdi_node_standalone_core::suppression::write_file(
            &dir,
            id,
            &gdi_node_standalone_core::suppression::Suppression {
                mode: gdi_node_standalone_core::suppression::SuppressMode::Remove,
                reason: "consent withdrawn".to_owned(),
                at: "2026-08-02T00:00:00Z".to_owned(),
            },
        )
        .unwrap();

        let incoming = serde_json::json!({
            "mode": "hide",
            "reason": "stale bundle",
            "at": "2026-08-01T00:00:00Z",
        });
        let mut stores = BTreeMap::new();
        let mut entries = BTreeMap::new();
        entries.insert(format!("{id}.json"), incoming);
        stores.insert("suppressions".to_owned(), entries);
        let bundle = Bundle {
            bundle_version: BUNDLE_VERSION,
            stores,
            history: BTreeMap::new(),
        };
        let known: BTreeMap<String, std::path::PathBuf> =
            [("suppressions".to_owned(), dir.clone())]
                .into_iter()
                .collect();

        // Writable: the replacement is recorded.
        let mut tally = WriteTally::default();
        write_bundle(&known, &bundle, &mut tally).unwrap();
        assert_eq!(tally.written, 1);
        assert_eq!(tally.replaced_total, 1, "a weaker overwrite must be named");

        // Read-only store: the write fails, and nothing is tallied.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        if test_util::skip_if_root() {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let mut tally = WriteTally::default();
        let outcome = write_bundle(&known, &bundle, &mut tally);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(outcome.is_err(), "a read-only store must fail the write");
        assert_eq!(
            tally.written, 0,
            "nothing landed, so nothing may be counted"
        );
        assert_eq!(
            tally.replaced_total, 0,
            "an entry that was never written cannot have replaced an in-force take-down"
        );
        assert!(tally.replaced.is_empty(), "and its key must not be audited");
    }
}
