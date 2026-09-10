//! Operator-authored, node-local dataset and channel suppression override store.
//!
//! One file per suppression under `<override_dir>/suppressions/`. The id or channel name is
//! the filename: `{id}.json` for a dataset, `channel-{name}.json` for a whole bucket or the
//! inbox. What is withheld therefore survives a corrupt file body. Reads fail closed: an
//! unparseable file suppresses its filename id or channel as `Hide`, never as `Remove`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::id::is_valid_dataset_id;
use crate::state::DatasetState;

/// How an operator override withholds a dataset from disclosure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SuppressMode {
    /// Withhold the dataset from disclosure; the underlying data is untouched.
    Hide,
    /// Withhold the dataset and treat it as gone (irreversible from the node's perspective).
    Remove,
}

impl SuppressMode {
    /// The wire, log and table spelling: `"hide"` or `"remove"`.
    ///
    /// Spelled here once, so it cannot drift between the consumers that render a mode as
    /// a string. Mirrors the `rename_all = "lowercase"` above, as an explicit `match`
    /// because callers need a `&'static str`, not a JSON value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hide => "hide",
            Self::Remove => "remove",
        }
    }
}

/// A single operator-authored suppression override.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    /// How the dataset is withheld.
    pub mode: SuppressMode,
    /// Free-text operator-supplied justification.
    #[serde(default)]
    pub reason: String,
    /// Free-text operator-supplied timestamp of when the override was authored.
    #[serde(default)]
    pub at: String,
}

/// The set of active operator suppression overrides, loaded fail-closed from disk.
#[derive(Debug, Default, Clone)]
pub struct SuppressionSet {
    datasets: BTreeMap<String, Suppression>,
    // `channel-{name}.json` entries: a whole bucket or the inbox withheld and
    // ingest-paused at once. `effective()` composes these with `datasets`; the bare
    // channel-level fact is `channel_get()`.
    channels: BTreeMap<String, Suppression>,
    degraded: usize,
    /// The store directory could not be read, as distinct from being absent. The set is
    /// therefore not authoritative and must not be adopted. See [`load`].
    unreadable: bool,
}

impl SuppressionSet {
    /// The suppression override for `id`, if any.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Suppression> {
        self.datasets.get(id)
    }

    /// Every dataset-level override id in the store, in any mode. See
    /// [`Self::channel_names`] for the channel-level counterpart.
    ///
    /// The operator-inventory source for a caller that must show an id even when it has no
    /// other record of it, such as `dataset list --suppressed`. An id whose `Remove` erase
    /// already purged its status entry stays visible in what the operator has suppressed.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.datasets.keys().map(String::as_str)
    }

    /// The operator's channel-level override for `channel`, if any.
    ///
    /// The bare record of mode, reason and time, independent of any id-level override on a
    /// member. [`Self::effective`] instead composes channel- and id-level into the
    /// most-restrictive verdict for one `(id, channel)` pair. This is what `channel list`
    /// displays, what `channel unhide` lifts, and what a whole-channel decision such as the
    /// bucket-monitor ingest-pause gate consults.
    #[must_use]
    pub fn channel_get(&self, channel: &str) -> Option<&Suppression> {
        self.channels.get(channel)
    }

    /// Every channel-level override name in the store, in any mode.
    ///
    /// Pairs with [`Self::ids`] as the operator-inventory source for `channel list`, so a
    /// channel whose config entry is gone or renamed still surfaces its override.
    pub fn channel_names(&self) -> impl Iterator<Item = &str> {
        self.channels.keys().map(String::as_str)
    }

    /// Whether the set holds no overrides at all, at dataset or channel level.
    ///
    /// Lets a caller distinguish "this node has never withheld anything" from "this node
    /// was withholding and the store is now gone", which is what the absent-store gauge
    /// reports.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.datasets.is_empty() && self.channels.is_empty()
    }

    /// The number of entries that failed to parse and were fail-closed to `Hide`.
    #[must_use]
    pub fn degraded(&self) -> usize {
        self.degraded
    }

    /// Whether the store directory could not be read, as distinct from being absent.
    ///
    /// `true` means this set is not authoritative: it is empty because the read failed, not
    /// because there are no withholds. A caller that adopts it lifts every operator
    /// withhold on an I/O fault. Keep the last-good set instead, and refuse to start at
    /// boot.
    #[must_use]
    pub fn unreadable(&self) -> bool {
        self.unreadable
    }

    /// Count active dataset-level overrides by mode: `(hide, remove)`.
    ///
    /// A tally of the override store itself rather than of which ids are currently cached,
    /// so it is stable across a cache-membership race. Dataset-level only, because
    /// `gdi_datasets_suppressed{mode}` is an id-level inventory gauge and a suppressed
    /// channel has its own `gdi_channel_suppressed{channel}` series.
    #[must_use]
    pub fn counts_by_mode(&self) -> (usize, usize) {
        let mut hide = 0;
        let mut remove = 0;
        for s in self.datasets.values() {
            match s.mode {
                SuppressMode::Hide => hide += 1,
                SuppressMode::Remove => remove += 1,
            }
        }
        (hide, remove)
    }

    /// The ids of every dataset-level `Remove` override in the store.
    ///
    /// Dataset-level only: a channel-level `Remove` names the channel, not any id, so a
    /// caller needing its member ids resolves them through the status index.
    ///
    /// This is the erasure-completeness source for a caller's disk-driven sweep. A `Remove`
    /// override's cache entry can be absent, for instance when `hydrate` skipped the id
    /// over a corrupt `manifest.json`, while `data_dir/{id}/` still exists, so a walk over
    /// the cache alone would never find it to erase.
    pub fn remove_ids(&self) -> impl Iterator<Item = &str> {
        self.datasets
            .iter()
            .filter(|(_, s)| s.mode == SuppressMode::Remove)
            .map(|(id, _)| id.as_str())
    }

    /// The operator's effective override for `(id, channel)`: the most restrictive of the
    /// id-level and channel-level suppression, where `Remove` beats `Hide`, or `None` if
    /// neither applies. An operator override always wins over the source state, which the
    /// caller composes separately.
    ///
    /// A channel suppression is scoped to its channel. A `channel-{name}.json` take-down
    /// withholds an id only while it is presented on channel `{name}`, so re-presenting the
    /// same id on another monitored channel is not covered by that entry. The trust
    /// boundary is the channel rather than the id: a key legitimate for one provider must
    /// not silence another provider's dataset of the same id. The channel-independent tool
    /// is `dataset take-down <id>`, which writes an `{id}.json` `Remove` that applies on
    /// every channel. A channel take-down does not synthesize per-member id-level markers,
    /// because the member set is unbounded and time-varying, so the store would grow
    /// without limit and never prune. See `docs/operating.md` for take-down scope.
    #[must_use]
    pub fn effective(&self, id: &str, channel: &str) -> Option<SuppressMode> {
        let id_mode = self.datasets.get(id).map(|s| s.mode);
        let ch_mode = self.channels.get(channel).map(|s| s.mode);
        match (id_mode, ch_mode) {
            (None, None) => None,
            (a, b) => Some(
                if a == Some(SuppressMode::Remove) || b == Some(SuppressMode::Remove) {
                    SuppressMode::Remove
                } else {
                    SuppressMode::Hide
                },
            ),
        }
    }

    /// The effective suppression record, not just the mode, for a listing that shows why an
    /// id is withheld. Returns whichever of the id-level or channel-level suppression
    /// carries the effective mode, preferring the more specific id-level one on a tie.
    /// `None` when neither applies.
    #[must_use]
    pub fn effective_full(&self, id: &str, channel: &str) -> Option<&Suppression> {
        let mode = self.effective(id, channel)?;
        let id_s = self.datasets.get(id);
        let ch_s = self.channels.get(channel);
        // One of the two filters always matches, so no further fallback is reachable.
        // `effective` returns `Some(mode)` only when at least one override exists, and one
        // of them carries that mode by construction.
        id_s.filter(|s| s.mode == mode)
            .or_else(|| ch_s.filter(|s| s.mode == mode))
    }

    /// The visibility that may be published for `id` on `channel`, given the `desired`
    /// state its source asked for.
    ///
    /// Operator authority is evaluated at the moment of publish, not the moment the work is
    /// accepted. Ingest gates suppression when it takes an artifact on, but the ingest that
    /// follows can run for minutes. A take-down issued in that window finds the id not yet
    /// cached, so it has nothing to hide, and the finishing ingest would publish the dataset
    /// visible. Anything suppressed is therefore withheld here whatever the source declared.
    /// A `Remove` is completed separately by `enforce_suppressions`, which needs the entry
    /// to exist first.
    #[must_use]
    pub fn publishable_state(
        &self,
        id: &str,
        channel: &str,
        desired: DatasetState,
    ) -> DatasetState {
        compose_state(desired, self.effective(id, channel).is_some())
    }
}

/// Compose an operator override onto a source-declared state: anything suppressed is
/// [`DatasetState::Hidden`], whatever its source asked for.
///
/// The rule lives here once because two callers must agree on it. The serving path reaches
/// it through [`SuppressionSet::publishable_state`] at publish time. The lock-free `dataset
/// list` and `GET /datasets` listing reaches it directly, composing the override store over
/// the persisted status index. Without it that listing would answer `visible` for a dataset
/// the node is withholding, while the state oracle answers `hidden` for the same id.
///
/// Takes a `bool` rather than the `Suppression`: the two callers resolve "is there an active
/// override here" differently, by mode and by full record, and neither needs the override's
/// content to answer this.
#[must_use]
pub fn compose_state(declared: DatasetState, suppressed: bool) -> DatasetState {
    if suppressed {
        DatasetState::Hidden
    } else {
        declared
    }
}

/// `<override_dir>/suppressions`.
#[must_use]
pub fn suppressions_subdir(override_dir: &Path) -> PathBuf {
    override_dir.join("suppressions")
}

/// The `channel-` filename prefix distinguishing a channel suppression
/// (`channel-{name}.json`) from a dataset one (`{id}.json`) in the same
/// `<override_dir>/suppressions/` directory.
const CHANNEL_FILE_PREFIX: &str = "channel-";

/// Whether `name` is safe as the path component of a channel suppression filename
/// (`channel-{name}.json`).
///
/// Requires a non-empty name of at most 128 bytes, with no path separator or NUL, so it
/// cannot escape the suppressions directory, and neither `.` nor `..`.
/// [`write_channel_file`] and [`remove_channel_file`] enforce this directly, whatever
/// additional "is this a configured channel" check a caller layers on top.
#[must_use]
pub fn is_valid_channel_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        // `unknown` is reserved. The management plane's dataset-state oracle reports a
        // cache hit with no status entry under that channel name and reads the channel
        // overrides for it, so a real channel called `unknown` would have its take-down
        // applied to every such id. Refused at the one definition every channel name
        // passes through, so no bucket can be minted with it.
        && name != "unknown"
        && !name.contains(['/', '\\', '\0'])
}

/// The path of `name`'s channel suppression file, or `InvalidInput` for a `name`
/// [`is_valid_channel_name`] would reject.
///
/// Every caller that interpolates a channel name into a path goes through here, so the
/// guard cannot be omitted at a new call site and the `channel-{name}.json` spelling has
/// exactly one definition.
fn channel_file_path(dir: &Path, name: &str) -> std::io::Result<PathBuf> {
    if !is_valid_channel_name(name) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid channel name {name:?}"),
        ));
    }
    Ok(dir.join(format!("{CHANNEL_FILE_PREFIX}{name}.json")))
}

/// The path of `id`'s dataset suppression file, or `InvalidInput` for an `id`
/// [`crate::id::is_valid_dataset_id`] would reject.
///
/// The dataset counterpart to [`channel_file_path`]. `load` admits only a valid dataset id
/// when reading the directory back, so an unguarded write could place a file the reader
/// then ignores, or a file outside the directory entirely.
fn dataset_file_path(dir: &Path, id: &str) -> std::io::Result<PathBuf> {
    // Delegates rather than re-implementing, so the sibling override stores that build the
    // same path shape share one definition of the guard.
    crate::override_store::store_file_path(dir, id)
}

/// What a `suppressions/` entry name is to the loader: a dataset override
/// (`{valid-id}.json`), a channel override (`channel-{valid-name}.json`), or nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderEntry<'a> {
    /// `{id}.json` for a valid dataset id.
    Dataset(&'a str),
    /// `channel-{name}.json` for a valid channel name.
    Channel(&'a str),
}

/// Classify one `suppressions/` entry by name, exactly as [`load`] admits it.
///
/// The one definition of what this store admits. [`load`] reads through it, and so does
/// [`crate::override_store::is_populated`], the used-marker input, so the marker counts
/// what the loader would load. A `.tmp.{pid}.{n}` left by a crashed durable write, a
/// `.gitkeep`, a `notes.json` or a `channel-` file with an unsafe name populates nothing,
/// because the node would apply nothing for it. Counting any entry instead would let a node
/// boot green under `require_override_store` over a store the loader reads as empty.
#[must_use]
pub fn classify_entry(file_name: &str) -> Option<LoaderEntry<'_>> {
    let stem = file_name.strip_suffix(".json")?;
    if let Some(channel) = stem.strip_prefix(CHANNEL_FILE_PREFIX) {
        return is_valid_channel_name(channel).then_some(LoaderEntry::Channel(channel));
    }
    is_valid_dataset_id(stem).then_some(LoaderEntry::Dataset(stem))
}

/// Delete `path`, treating an already-absent file as success. `Ok(true)` when a file was
/// removed, `Ok(false)` when there was nothing to remove. The caller keys the store's used
/// marker on that, so a lift that removed nothing must not read as "the store was emptied".
fn remove_ignoring_missing(path: &Path) -> std::io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Read one suppression file, failing closed.
///
/// A body that cannot be read or parsed still yields a suppression, because the filename
/// carries the id or channel. It becomes a `Hide`, never an irreversible `Remove`, and bumps
/// `degraded`. The dataset and channel paths share this definition so they cannot drift on
/// what failing closed means.
fn read_fail_closed(path: &Path, degraded: &mut usize) -> Suppression {
    if let Some(s) = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Suppression>(&b).ok())
    {
        return s;
    }
    *degraded += 1;
    Suppression {
        mode: SuppressMode::Hide,
        reason: "<unparseable suppression file>".to_owned(),
        at: String::new(),
    }
}

/// Load the suppression set from the suppressions directory, failing closed.
///
/// Never errors. A missing directory is empty. An unreadable or unparseable `{id}.json` or
/// `channel-{name}.json` still suppresses that filename id or channel as `Hide` and bumps
/// `degraded`. Only a valid dataset id, or a `channel-` prefix followed by a name
/// [`is_valid_channel_name`] accepts, is considered; anything else is ignored.
#[must_use]
pub fn load(dir: &Path) -> SuppressionSet {
    let mut set = SuppressionSet::default();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        // Absent is the accepted trade-off: a node that never suppressed anything is
        // indistinguishable on disk from one whose store was destroyed, and
        // `require_override_store` exists for operators who cannot accept that.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return set,
        // Unreadable is a different case. EACCES, EIO or ESTALE on a network volume and
        // EMFILE under fd exhaustion each say "cannot tell", which is the opposite of
        // "nothing here". Collapsing them into the empty set would make an I/O fault look
        // like "no withholds" and lift every operator withhold on the public Beacon and FDP
        // planes until the next reload.
        //
        // Flagged rather than returned as an error, so the signature and its call sites are
        // unchanged and the caller keeps its last-good set. Not gated on
        // `require_override_store`: that flag buys certainty about absence, and a read error
        // is already unambiguous.
        Err(e) => {
            tracing::error!(
                alert = true,
                event.action = "suppression.store.read",
                event.outcome = "failure",
                dir = %dir.display(),
                error = %e,
                "suppression store directory is unreadable; the last-good set is kept \
                 rather than adopting an empty one"
            );
            set.unreadable = true;
            return set;
        }
    };
    for entry in entries {
        // A per-entry `readdir` error yields no filename, so there is no specific id to
        // fail closed on. Surface it through `degraded`, which the reload path logs and
        // gauges, rather than dropping it silently with `.flatten()`.
        let Ok(entry) = entry else {
            set.degraded += 1;
            continue;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        match classify_entry(name) {
            Some(LoaderEntry::Channel(channel)) => {
                let s = read_fail_closed(&entry.path(), &mut set.degraded);
                set.channels.insert(channel.to_owned(), s);
            }
            Some(LoaderEntry::Dataset(id)) => {
                let s = read_fail_closed(&entry.path(), &mut set.degraded);
                set.datasets.insert(id.to_owned(), s);
            }
            // Junk skipped here.
            None => {}
        }
    }
    set
}

/// Load the suppression set for a one-shot command, refusing when the store exists but
/// cannot be read.
///
/// [`load`] flags an unreadable store and hands back the empty set so a running node can
/// keep its last-good one. That is right for the serve path and wrong for a command with no
/// last-good set: reporting "no withholds exist" when the truth is "the withholds could not
/// be read" gives an operator the opposite answer on a disclosure-control surface.
///
/// Reporting commands must use this rather than reading [`SuppressionSet::unreadable`]
/// themselves, because an ignored advisory bool is indistinguishable from a healthy store.
/// It applies [`crate::override_store::readable_or_absent`]'s distinction, tolerating
/// absence and refusing an I/O fault, in the shape those commands need. An absent store is
/// still `Ok` with an empty set: a node that has never withheld anything is a normal node.
///
/// # Errors
/// The underlying `read_dir` error when the directory exists but cannot be opened.
pub fn load_or_report(dir: &Path) -> std::io::Result<SuppressionSet> {
    let set = load(dir);
    if set.unreadable() {
        // Re-stat only to recover the errno for the message, since `load` records that the
        // read failed but not why. If the store became readable in between, the set in hand
        // is still the unreadable one, so this must not turn into a success.
        return Err(crate::override_store::readable_or_absent(dir)
            .err()
            .unwrap_or_else(|| {
                std::io::Error::other("override store could not be read".to_owned())
            }));
    }
    Ok(set)
}

/// Write one dataset suppression file atomically, creating the suppressions directory if
/// needed.
///
/// # Errors
/// Returns `InvalidInput` for an `id` that is not a valid dataset id, and propagates I/O
/// errors from directory creation, serialization, or the durable write.
pub fn write_file(dir: &Path, id: &str, s: &Suppression) -> std::io::Result<()> {
    let path = dataset_file_path(dir, id)?;
    // Creates the sibling loader directory too, so the first override of any kind leaves
    // the store exportable. See `override_store::create_store_dir`.
    crate::override_store::create_store_dir(dir)?;
    let json = serde_json::to_vec_pretty(s).map_err(std::io::Error::other)?;
    crate::util::write_durable_atomic_private(&path, &json)
}

/// Write one channel suppression file atomically as `channel-{name}.json`, creating the
/// suppressions directory if needed. Rejects a `name` [`is_valid_channel_name`] would
/// reject, whatever the caller.
///
/// # Errors
/// Returns `InvalidInput` for an unsafe `name`; otherwise propagates I/O errors from
/// directory creation, serialization, or the durable write.
pub fn write_channel_file(dir: &Path, name: &str, s: &Suppression) -> std::io::Result<()> {
    let path = channel_file_path(dir, name)?;
    // Creates the sibling loader directory too, so the first override of any kind leaves
    // the store exportable. See `override_store::create_store_dir`.
    crate::override_store::create_store_dir(dir)?;
    let json = serde_json::to_vec_pretty(s).map_err(std::io::Error::other)?;
    crate::util::write_durable_atomic_private(&path, &json)
}

/// Remove one channel suppression file: `Ok(true)` when a file was removed, `Ok(false)`
/// when it was already absent.
///
/// # Errors
/// Returns `InvalidInput` for an unsafe `name`; otherwise propagates I/O errors other
/// than `NotFound`.
pub fn remove_channel_file(dir: &Path, name: &str) -> std::io::Result<bool> {
    remove_ignoring_missing(&channel_file_path(dir, name)?)
}

/// Remove one suppression file: `Ok(true)` when a file was removed, `Ok(false)` when it
/// was already absent.
///
/// # Errors
/// Returns `InvalidInput` for an `id` that is not a valid dataset id, and propagates I/O
/// errors other than `NotFound`.
pub fn remove_file(dir: &Path, id: &str) -> std::io::Result<bool> {
    remove_ignoring_missing(&dataset_file_path(dir, id)?)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

    #[test]
    fn classify_entry_admits_exactly_what_load_admits() {
        use super::{LoaderEntry, classify_entry};
        assert_eq!(
            classify_entry("GDI-EE-UTARTU-20260409143052837.json"),
            Some(LoaderEntry::Dataset("GDI-EE-UTARTU-20260409143052837"))
        );
        assert_eq!(
            classify_entry("channel-primary.json"),
            Some(LoaderEntry::Channel("primary"))
        );
        for junk in [
            "GDI-EE-UTARTU-20260409143052837.json.tmp.123.4",
            "GDI-EE-UTARTU-20260409143052837",
            "gdi-ee-utartu-20260409143052837.json",
            "ds-1.json",
            "notes.json",
            ".gitkeep",
            "channel-.json",
            "channel-..json",
            "channel-a\\b.json",
        ] {
            assert_eq!(classify_entry(junk), None, "{junk:?} must be junk");
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_store_is_distinguished_from_an_absent_one() {
        // Returning the empty set for both would make an EACCES, an EIO or ESTALE on a
        // network volume, or an EMFILE under fd exhaustion indistinguishable from "this node
        // has no withholds", and the caller would adopt it, lifting every operator withhold
        // on the public planes until the next reload. `require_override_store`, which
        // defaults to false, is not a substitute.
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();

        // An absent store stays the empty-set case, the ambiguity the design accepts.
        let absent = tmp.path().join("nope");
        let set = super::load(&absent);
        assert!(
            !set.unreadable(),
            "an absent dir must NOT report unreadable: that ambiguity is the accepted \
             trade-off, and `require_override_store` is the opt-in for operators who \
             cannot accept it"
        );

        let dir = tmp.path().join("suppressions");
        std::fs::create_dir_all(&dir).unwrap();
        let s = super::Suppression {
            mode: super::SuppressMode::Hide,
            reason: "consent withdrawn".to_owned(),
            at: "2026-08-05T00:00:00Z".to_owned(),
        };
        super::write_file(&dir, "GOE-EE-UTARTU-1", &s).unwrap();
        assert!(
            !super::load(&dir).is_empty(),
            "precondition: the withhold loads"
        );

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root bypasses EACCES, so the scenario is untestable here if the dir still opens.
        // Say so out loud: a silent `return` would report green having verified only the
        // absent half.
        if std::fs::read_dir(&dir).is_ok() {
            #[expect(
                clippy::print_stderr,
                reason = "the skip has to be visible in the run output"
            )]
            {
                eprintln!(
                    "skipped (uid 0 or permissive fs): a 0o000 dir is still readable here, \
                     so the unreadable half of this test verified nothing. Re-run as \
                     non-root."
                );
            }
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
            return;
        }

        let set = super::load(&dir);
        assert!(
            set.unreadable(),
            "a present-but-unreadable store must report UNREADABLE so the caller keeps its \
             last-good set; reporting an empty set here lifts every withhold"
        );
        assert!(
            set.is_empty(),
            "it is still empty — it just is not authoritative"
        );

        // A reporting caller must not be able to adopt that empty set by omission.
        // `unreadable()` is advisory, and an ignored advisory would let `doctor` publish
        // `withheld = 0` against this very store. `load_or_report` makes it an error the
        // caller has to handle, while leaving `load`'s shape for the serve path.
        let reported = super::load_or_report(&dir);
        assert!(
            reported.is_err(),
            "a one-shot reporting caller must get an ERROR, not an empty set it will print \
             as 'nothing is withheld'"
        );

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();

        // An absent store stays Ok: a node that has never withheld anything is a normal
        // node, and conflating the two would make every such node fail these commands.
        let never_used = tmp.path().join("no-store-here");
        let set = super::load_or_report(&never_used).expect("an absent store is not an error");
        assert!(set.is_empty());
    }

    #[test]
    fn the_dataset_half_refuses_a_traversal_id_like_the_channel_half_does() {
        // Both halves route every name through a path builder that validates it, so
        // neither `write_file` nor `remove_file` can interpolate an id into a path
        // unchecked.
        let dir = tmp();
        let sub = dir.path().join("suppressions");
        let s = Suppression {
            mode: SuppressMode::Hide,
            reason: "test".to_owned(),
            at: String::new(),
        };

        for bad in ["../escaped", "a/b", "..", "", "with\0nul"] {
            let err = write_file(&sub, bad, &s)
                .expect_err("a dataset id that is not a valid id must be refused");
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidInput,
                "id {bad:?} must be rejected as invalid input, not attempted"
            );
            assert!(
                remove_file(&sub, bad).is_err(),
                "removal must refuse the same shapes it refuses to write: {bad:?}"
            );
        }
        // A real dataset id still round-trips.
        write_file(&sub, ID, &s).unwrap();
        assert!(load(&sub).get(ID).is_some());
        remove_file(&sub, ID).unwrap();
    }

    use super::*;
    use std::fs;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }
    const ID: &str = "GDI-EE-UTARTU-20260409143052837";

    #[test]
    fn as_str_is_the_lowercase_wire_spelling() {
        assert_eq!(SuppressMode::Hide.as_str(), "hide");
        assert_eq!(SuppressMode::Remove.as_str(), "remove");
    }

    #[test]
    fn publishable_state_withholds_a_suppressed_id() {
        // The publish moment is not the enqueue moment. Ingest gates suppression when it
        // accepts an artifact, but a large ingest runs for minutes afterwards, and a
        // take-down issued in that window finds the id not yet cached. The publish path has
        // to re-ask.
        let mut set = SuppressionSet::default();
        set.datasets.insert(
            ID.to_owned(),
            Suppression {
                mode: SuppressMode::Hide,
                reason: "take-down".to_owned(),
                at: String::new(),
            },
        );
        assert_eq!(
            set.publishable_state(ID, "inbox", DatasetState::Visible),
            DatasetState::Hidden,
            "a suppressed id must never be published Visible"
        );
    }

    #[test]
    fn publishable_state_withholds_on_a_channel_suppression() {
        let mut set = SuppressionSet::default();
        set.channels.insert(
            "primary".to_owned(),
            Suppression {
                mode: SuppressMode::Remove,
                reason: "provider withdrawn".to_owned(),
                at: String::new(),
            },
        );
        assert_eq!(
            set.publishable_state(ID, "primary", DatasetState::Visible),
            DatasetState::Hidden,
        );
    }

    #[test]
    fn publishable_state_passes_an_unsuppressed_id_through() {
        let set = SuppressionSet::default();
        assert_eq!(
            set.publishable_state(ID, "inbox", DatasetState::Visible),
            DatasetState::Visible,
        );
        assert_eq!(
            set.publishable_state(ID, "inbox", DatasetState::Hidden),
            DatasetState::Hidden,
        );
    }

    #[test]
    fn load_empty_or_missing_dir_is_empty() {
        let d = tmp();
        let set = load(&d.path().join("suppressions")); // missing subdir
        assert_eq!(set.degraded(), 0);
        assert!(set.get(ID).is_none());
    }

    #[test]
    fn load_reads_a_valid_hide_file() {
        let d = tmp();
        let sub = suppressions_subdir(d.path());
        fs::create_dir_all(&sub).unwrap();
        fs::write(
            sub.join(format!("{ID}.json")),
            br#"{"mode":"hide","reason":"embargo","at":"2026-07-11T00:00:00Z"}"#,
        )
        .unwrap();
        let set = load(&sub);
        let s = set.get(ID).expect("present");
        assert_eq!(s.mode, SuppressMode::Hide);
        assert_eq!(s.reason, "embargo");
        assert_eq!(set.degraded(), 0);
    }

    #[test]
    fn corrupt_body_fails_closed_to_hide_and_counts_degraded() {
        let d = tmp();
        let sub = suppressions_subdir(d.path());
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join(format!("{ID}.json")), b"{ this is not json").unwrap();
        let set = load(&sub);
        let s = set.get(ID).expect("still suppressed; id is the filename");
        assert_eq!(
            s.mode,
            SuppressMode::Hide,
            "fail closed to hide, NEVER remove"
        );
        assert_eq!(set.degraded(), 1);
    }

    #[test]
    fn non_json_and_non_id_files_are_ignored() {
        let d = tmp();
        let sub = suppressions_subdir(d.path());
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("README"), b"x").unwrap(); // no .json
        fs::write(sub.join("not-an-id.json"), b"{}").unwrap(); // invalid dataset id
        let set = load(&sub);
        assert_eq!(set.degraded(), 0);
        assert!(set.get("not-an-id").is_none());
    }

    #[test]
    fn effective_none_when_absent() {
        let set = SuppressionSet::default();
        assert_eq!(set.effective("X", "inbox"), None);
    }

    #[test]
    fn effective_returns_the_id_mode() {
        let mut set = SuppressionSet::default();
        set.datasets.insert(
            "X".into(),
            Suppression {
                mode: SuppressMode::Hide,
                reason: String::new(),
                at: String::new(),
            },
        );
        assert_eq!(set.effective("X", "inbox"), Some(SuppressMode::Hide));
    }

    #[test]
    fn effective_returns_remove_when_id_mode_is_remove() {
        // Covers the `a`-half of `effective`'s `a == Some(Remove) || b == Some(Remove)`:
        // an id-level `Remove` with no channel override, and with a `Hide` channel override
        // that must not downgrade it.
        let mut set = SuppressionSet::default();
        set.datasets.insert(
            "X".into(),
            Suppression {
                mode: SuppressMode::Remove,
                reason: String::new(),
                at: String::new(),
            },
        );
        assert_eq!(set.effective("X", "inbox"), Some(SuppressMode::Remove));

        set.channels.insert(
            "egv".into(),
            Suppression {
                mode: SuppressMode::Hide,
                reason: String::new(),
                at: String::new(),
            },
        );
        // id=Remove, channel=Hide -> Remove still wins (most restrictive).
        assert_eq!(set.effective("X", "egv"), Some(SuppressMode::Remove));
    }

    /// `effective_full` over every combination of id-level and channel-level override.
    ///
    /// It must return the record carrying the effective mode, so an operator listing shows
    /// the reason that explains the withholding, preferring the more specific id-level one
    /// when both carry it. The `reason` field tags which record came back.
    #[test]
    fn effective_full_returns_the_record_carrying_the_effective_mode() {
        fn s(mode: SuppressMode, tag: &str) -> Suppression {
            Suppression {
                mode,
                reason: tag.to_owned(),
                at: String::new(),
            }
        }
        use SuppressMode::{Hide, Remove};
        // (id override, channel override, expected reason tag)
        let cases: &[(Option<SuppressMode>, Option<SuppressMode>, Option<&str>)] = &[
            (None, None, None),
            (Some(Hide), None, Some("id")),
            (Some(Remove), None, Some("id")),
            (None, Some(Hide), Some("ch")),
            (None, Some(Remove), Some("ch")),
            // Both present, same mode -> the id-level record wins (more specific).
            (Some(Hide), Some(Hide), Some("id")),
            (Some(Remove), Some(Remove), Some("id")),
            // Both present, differing -> whichever carries the most-restrictive mode.
            (Some(Hide), Some(Remove), Some("ch")),
            (Some(Remove), Some(Hide), Some("id")),
        ];
        for (id_mode, ch_mode, want) in cases {
            let mut set = SuppressionSet::default();
            if let Some(m) = *id_mode {
                set.datasets.insert("X".into(), s(m, "id"));
            }
            if let Some(m) = *ch_mode {
                set.channels.insert("egv".into(), s(m, "ch"));
            }
            let got = set.effective_full("X", "egv").map(|r| r.reason.as_str());
            assert_eq!(
                got, *want,
                "id={id_mode:?} channel={ch_mode:?}: wrong record returned"
            );
        }
    }

    #[test]
    fn effective_most_restrictive_across_id_and_channel() {
        let mut set = SuppressionSet::default();
        set.datasets.insert(
            "X".into(),
            Suppression {
                mode: SuppressMode::Hide,
                reason: String::new(),
                at: String::new(),
            },
        );
        set.channels.insert(
            "egv".into(),
            Suppression {
                mode: SuppressMode::Remove,
                reason: String::new(),
                at: String::new(),
            },
        );
        // id=Hide, channel=Remove -> Remove wins (most restrictive).
        assert_eq!(set.effective("X", "egv"), Some(SuppressMode::Remove));
    }

    #[test]
    fn ids_lists_every_dataset_level_entry_regardless_of_mode() {
        let mut set = SuppressionSet::default();
        set.datasets.insert(
            "A".into(),
            Suppression {
                mode: SuppressMode::Hide,
                reason: String::new(),
                at: String::new(),
            },
        );
        set.datasets.insert(
            "B".into(),
            Suppression {
                mode: SuppressMode::Remove,
                reason: String::new(),
                at: String::new(),
            },
        );
        let mut ids: Vec<&str> = set.ids().collect();
        ids.sort_unstable();
        assert_eq!(ids, ["A", "B"]);
    }

    #[test]
    fn remove_ids_lists_only_dataset_level_remove_entries() {
        let mut set = SuppressionSet::default();
        set.datasets.insert(
            "A".into(),
            Suppression {
                mode: SuppressMode::Hide,
                reason: String::new(),
                at: String::new(),
            },
        );
        set.datasets.insert(
            "B".into(),
            Suppression {
                mode: SuppressMode::Remove,
                reason: String::new(),
                at: String::new(),
            },
        );
        set.datasets.insert(
            "C".into(),
            Suppression {
                mode: SuppressMode::Remove,
                reason: String::new(),
                at: String::new(),
            },
        );
        let mut ids: Vec<&str> = set.remove_ids().collect();
        ids.sort_unstable();
        assert_eq!(ids, ["B", "C"]);
    }

    #[test]
    fn counts_by_mode_tallies_hide_and_remove_separately() {
        let mut set = SuppressionSet::default();
        assert_eq!(set.counts_by_mode(), (0, 0));
        set.datasets.insert(
            "A".into(),
            Suppression {
                mode: SuppressMode::Hide,
                reason: String::new(),
                at: String::new(),
            },
        );
        set.datasets.insert(
            "B".into(),
            Suppression {
                mode: SuppressMode::Remove,
                reason: String::new(),
                at: String::new(),
            },
        );
        set.datasets.insert(
            "C".into(),
            Suppression {
                mode: SuppressMode::Hide,
                reason: String::new(),
                at: String::new(),
            },
        );
        assert_eq!(set.counts_by_mode(), (2, 1));
    }

    #[test]
    fn write_then_load_then_remove_roundtrip() {
        let d = tmp();
        let sub = suppressions_subdir(d.path());
        let s = Suppression {
            mode: SuppressMode::Remove,
            reason: "consent withdrawn".into(),
            at: "2026-07-11T00:00:00Z".into(),
        };
        write_file(&sub, ID, &s).unwrap();
        let set = load(&sub);
        assert_eq!(set.get(ID).unwrap().mode, SuppressMode::Remove);
        remove_file(&sub, ID).unwrap();
        assert!(load(&sub).get(ID).is_none());
        remove_file(&sub, ID).unwrap(); // idempotent when already gone
    }

    // Channel-level suppression.

    #[test]
    fn is_valid_channel_name_rejects_unsafe_names() {
        assert!(is_valid_channel_name("primary"));
        assert!(is_valid_channel_name("inbox"));
        assert!(
            !is_valid_channel_name("unknown"),
            "`unknown` is the state oracle's placeholder for an id with no status entry"
        );
        assert!(!is_valid_channel_name(""));
        assert!(!is_valid_channel_name("."));
        assert!(!is_valid_channel_name(".."));
        assert!(!is_valid_channel_name("../../etc/passwd"));
        assert!(!is_valid_channel_name("a/b"));
        assert!(!is_valid_channel_name("a\\b"));
        assert!(!is_valid_channel_name("a\0b"));
        assert!(!is_valid_channel_name(&"x".repeat(129)));
        assert!(is_valid_channel_name(&"x".repeat(128)));
    }

    #[test]
    fn load_reads_a_valid_channel_file_and_leaves_datasets_empty() {
        let d = tmp();
        let sub = suppressions_subdir(d.path());
        fs::create_dir_all(&sub).unwrap();
        fs::write(
            sub.join("channel-primary.json"),
            br#"{"mode":"remove","reason":"provider compromised","at":"2026-07-11T00:00:00Z"}"#,
        )
        .unwrap();
        let set = load(&sub);
        let s = set.channel_get("primary").expect("present");
        assert_eq!(s.mode, SuppressMode::Remove);
        assert_eq!(s.reason, "provider compromised");
        assert_eq!(set.degraded(), 0);
        assert!(set.get("primary").is_none(), "not a dataset-id entry");
        assert_eq!(set.channel_names().collect::<Vec<_>>(), ["primary"]);
    }

    #[test]
    fn load_channel_and_dataset_files_do_not_collide() {
        let d = tmp();
        let sub = suppressions_subdir(d.path());
        fs::create_dir_all(&sub).unwrap();
        write_file(
            &sub,
            ID,
            &Suppression {
                mode: SuppressMode::Hide,
                reason: "id".into(),
                at: String::new(),
            },
        )
        .unwrap();
        write_channel_file(
            &sub,
            "primary",
            &Suppression {
                mode: SuppressMode::Remove,
                reason: "channel".into(),
                at: String::new(),
            },
        )
        .unwrap();
        let set = load(&sub);
        assert_eq!(set.get(ID).unwrap().mode, SuppressMode::Hide);
        assert_eq!(
            set.channel_get("primary").unwrap().mode,
            SuppressMode::Remove
        );
    }

    #[test]
    fn corrupt_channel_body_fails_closed_to_hide_and_counts_degraded() {
        let d = tmp();
        let sub = suppressions_subdir(d.path());
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("channel-primary.json"), b"{ not json").unwrap();
        let set = load(&sub);
        let s = set.channel_get("primary").expect("still suppressed");
        assert_eq!(
            s.mode,
            SuppressMode::Hide,
            "fail closed to hide, NEVER remove"
        );
        assert_eq!(set.degraded(), 1);
    }

    #[test]
    fn load_ignores_a_channel_file_with_an_unsafe_embedded_name() {
        // A filename containing a traversal-looking channel name is still one filesystem
        // entry with no real `/`, but `is_valid_channel_name` rejects it as junk rather
        // than accepting a channel called "..".
        let d = tmp();
        let sub = suppressions_subdir(d.path());
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("channel-...json"), b"{}").unwrap(); // name = ".." after strip
        let set = load(&sub);
        assert_eq!(set.degraded(), 0);
        assert_eq!(set.channel_names().count(), 0);
    }

    #[test]
    fn write_channel_file_rejects_an_unsafe_name() {
        let d = tmp();
        let sub = suppressions_subdir(d.path());
        let s = Suppression {
            mode: SuppressMode::Hide,
            reason: "x".into(),
            at: String::new(),
        };
        assert!(write_channel_file(&sub, "../evil", &s).is_err());
        assert!(remove_channel_file(&sub, "../evil").is_err());
        // And nothing escaped the suppressions dir.
        assert!(!d.path().join("evil.json").exists());
    }

    #[test]
    fn write_then_load_then_remove_channel_roundtrip() {
        let d = tmp();
        let sub = suppressions_subdir(d.path());
        let s = Suppression {
            mode: SuppressMode::Remove,
            reason: "compromised".into(),
            at: "2026-07-11T00:00:00Z".into(),
        };
        write_channel_file(&sub, "primary", &s).unwrap();
        let set = load(&sub);
        assert_eq!(
            set.channel_get("primary").unwrap().mode,
            SuppressMode::Remove
        );
        remove_channel_file(&sub, "primary").unwrap();
        assert!(load(&sub).channel_get("primary").is_none());
        remove_channel_file(&sub, "primary").unwrap(); // idempotent when already gone
    }

    #[test]
    fn effective_composes_channel_only_suppression() {
        // With no id-level entry, a channel-level `Hide` still makes `effective` return
        // `Some` for every id of that channel. That is what lets the ingest gates and the
        // cache-withhold walk block an id never seen before, from the channel file alone.
        let mut set = SuppressionSet::default();
        set.channels.insert(
            "primary".into(),
            Suppression {
                mode: SuppressMode::Hide,
                reason: String::new(),
                at: String::new(),
            },
        );
        assert_eq!(
            set.effective("never-seen-id", "primary"),
            Some(SuppressMode::Hide)
        );
        assert_eq!(set.effective("never-seen-id", "other-channel"), None);
    }
}
