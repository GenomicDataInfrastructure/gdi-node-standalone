//! The `datasets` one-shot subcommand: a read-only listing of the persistent status
//! index (`datasets/.status.json`) with operator filters.
//!
//! Runs without the data-dir writer lock, so it is safe to invoke while the node is
//! serving. The index is written atomically (tmp plus `rename`), so a concurrent reader
//! always sees a complete old-or-new snapshot, never a torn file. It reads the on-disk
//! index, which the node persists on every mutation, so a source-declared
//! `visible`<->`hidden` flip may lag by at most one reconcile. Provenance, channel and
//! error markers are authoritative there.
//!
//! An operator override does not lag, and is not in that index at all: the running node
//! applies a withhold to its in-memory cache only (`AppState::apply_suppressions_to_cache`),
//! and the index keeps the source-declared state forever. The two facts are composed here,
//! through the same [`compose_state`] rule the serving path publishes through (its
//! [`SuppressionSet::publishable_state`]) — see [`ListedDataset::state`]. Reporting the
//! index value raw would let this listing, and `GET /datasets` which renders the same rows,
//! answer `visible` for a dataset the node is actively withholding while
//! `GET /datasets/{id}/state` answers `hidden` for the same id at the same instant.
//!
//! This is the standalone-operation substitute for an integrating system's "which datasets
//! came from whom" query. It filters on four operational axes: health (`--state` and
//! `--errors`), source and provenance (`--channel`, `--provenance`, `--writer`,
//! `--unverified`), identity (`--id`), and operator override (`--suppressed`). It emits an
//! aligned table, or `--format json` for scripting.
//!
//! The `--suppressed` axis and the `SUPPRESSED` column read a second on-disk store,
//! `<override_dir>/suppressions/*.json` (see [`gdi_node_standalone_core::suppression`]),
//! loaded the same fail-closed, lock-free way as the status index. It may likewise lag a
//! suppression written moments ago until the node's next `SIGUSR1` or reconcile, but the
//! file itself, this listing's source, is authoritative the instant it lands.

use anyhow::{Context as _, Result, bail};
use serde::Serialize;

use gdi_node_standalone_core::cache::{DatasetProvenance, StatusEntry, StatusIndex};
use gdi_node_standalone_core::config::{Reloadable, ServiceConfig};
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::suppression::{self, Suppression, SuppressionSet, compose_state};

/// Valid `--state` values. Mirrors [`DatasetState`]'s `as_str` spellings; kept here (not
/// derived) because the CLI validates operator input before any lookup.
const STATE_KINDS: [&str; 4] = ["visible", "hidden", "error", "processing"];

/// The `datasets` output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum OutputFormat {
    /// A human-readable aligned table (default).
    #[default]
    Text,
    /// A machine-readable JSON array — one object per dataset.
    Json,
}

/// The operator-supplied `datasets` filters. An empty filter matches every dataset.
///
/// Every predicate must hold (logical AND across flags). `states` matches if the entry's
/// state is any one listed (logical OR within the flag). `--errors` is sugar that pushes
/// `error` onto `states`.
///
/// `PartialEq` so the CLI can detect "any `datasets` flag was set" (`!= default`) when it
/// validates that the given flags belong to the selected subcommand.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DatasetsFilter {
    /// `--state <s>` (repeatable): keep only these [`DatasetState`]s.
    pub states: Vec<String>,
    /// `--channel <name>`: keep only this source (a bucket's logical name or `inbox`).
    pub channel: Option<String>,
    /// `--provenance <kind>`: keep only this [`DatasetProvenance`] kind.
    pub provenance: Option<String>,
    /// `--writer <substr>`: keep only datasets a matching writer fingerprint published.
    pub writer: Option<String>,
    /// `--id <substr>`: keep only ids containing this substring.
    pub id_substring: Option<String>,
    /// `--unverified`: keep only datasets whose provenance is not `recovered` (no writer
    /// key of any kind), the set an operator reviews before enabling a writer allow-list.
    pub unverified: bool,
    /// `--suppressed`: keep only datasets carrying an active operator suppression
    /// override (`hide` or `remove`) — mirrors `--unverified`'s "keep only" boolean
    /// shape (a `--suppress-mode <hide|remove>` value filter is not offered: the two
    /// modes are few enough that `--format json` + a client-side filter covers it).
    pub suppressed: bool,
}

impl DatasetsFilter {
    /// Reject filter values the enums do not recognize, with a message naming the valid
    /// set — the same anti-typo posture as the top-level flag parser.
    ///
    /// # Errors
    ///
    /// Returns an error naming the bad value and the accepted set.
    pub fn validate(&self) -> Result<()> {
        for state in &self.states {
            if !STATE_KINDS.contains(&state.as_str()) {
                bail!(
                    "invalid --state `{state}`; expected one of {}",
                    STATE_KINDS.join(", ")
                );
            }
        }
        if let Some(kind) = &self.provenance
            && !DatasetProvenance::KINDS.contains(&kind.as_str())
        {
            bail!(
                "invalid --provenance `{kind}`; expected one of {}",
                DatasetProvenance::KINDS.join(", ")
            );
        }
        Ok(())
    }

    /// Whether `--state` (and its `--errors` sugar) accepts this row.
    ///
    /// Matches the effective state, so `--state hidden` finds an operator withhold and what
    /// the filter selected is what the row prints. One carve-out: a `source` of `error` also
    /// matches, because `error` is a health fact rather than a visibility one. No override
    /// can produce it, and hiding a broken dataset does not repair it. Without the carve-out,
    /// composing the override would drop errored-and-withheld rows from `--errors`, the set
    /// an operator triaging failures asks for. `processing` needs no carve-out: it is never
    /// persisted to the index.
    fn state_matches(&self, source: DatasetState, effective: DatasetState) -> bool {
        self.states.iter().any(|want| {
            want == effective.as_str() || (source == DatasetState::Error && want == source.as_str())
        })
    }

    /// Whether a single status entry passes every active predicate. `effective` is the
    /// override-composed state from [`compose_state`], and `withheld` is the input it
    /// was composed from: either an operator override, from the separate suppressions store
    /// described in the module doc, or the orphan-channel withhold. `--suppressed` keys on
    /// that input, because an orphan-withheld dataset has no override record, and keying on
    /// the record alone would leave it off the withheld inventory while `doctor` counts it
    /// as withheld and the plain listing shows it `hidden`.
    fn matches(
        &self,
        id: &str,
        entry: &StatusEntry,
        effective: DatasetState,
        withheld: bool,
    ) -> bool {
        if !self.states.is_empty() && !self.state_matches(entry.state, effective) {
            return false;
        }
        if let Some(channel) = &self.channel
            && entry.channel != *channel
        {
            return false;
        }
        if let Some(kind) = &self.provenance
            && entry.provenance.kind() != kind
        {
            return false;
        }
        if self.unverified && entry.provenance.kind() == "recovered" {
            return false;
        }
        if let Some(needle) = &self.writer
            && !entry
                .provenance
                .fingerprints()
                .iter()
                .any(|fp| fp.contains(needle))
        {
            return false;
        }
        if let Some(needle) = &self.id_substring
            && !id.contains(needle)
        {
            return false;
        }
        if self.suppressed && !withheld {
            return false;
        }
        true
    }
}

/// One listed dataset: the typed core [`collect`] produces, which both the `dataset list`
/// CLI and the management plane's `GET /datasets` render.
///
/// This is also the JSON wire shape for both of them. Deriving the serialization from
/// the same struct the CLI renders is what makes "the route and the CLI agree" structural
/// rather than a promise. The alternative, a second row type beside this one, drifts the
/// moment a field is added to either. Field order is the emitted key order and is part of
/// that contract.
///
/// Owned rather than borrowed because an HTTP handler outlives the index it loaded; the
/// listing is bounded by the status index, so the copies are not a concern.
#[derive(Debug, Clone, Serialize)]
pub struct ListedDataset {
    /// The dataset id.
    pub id: String,
    /// The effective serving state: the source-declared state of [`Self::source_state`]
    /// with any active operator override composed over it, exactly as the serving path
    /// composes it ([`SuppressionSet::publishable_state`]). An override always wins, so a
    /// withheld dataset reports `hidden` here whatever its source asked for — the same
    /// answer `GET /datasets/{id}/state` gives for that id (both of its arms: the cache
    /// one is withheld in place by `apply_suppressions_to_cache`, and the index-only one
    /// composes exactly as this listing does).
    pub state: DatasetState,
    /// The owning channel (a bucket's logical name, or `inbox`).
    pub channel: String,
    /// How the publishing writer key was (or was not) recovered.
    pub provenance: DatasetProvenance,
    /// The active operator suppression override mode, absent (not `null`) when
    /// unsuppressed — mirrors the oracle's `suppression` field omission convention
    /// (`datasets_http::StateBody`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<&'static str>,
    /// The operator-supplied justification for the suppression, absent when unsuppressed, so
    /// a successor operator sees why an id is withheld and not just that it is.
    ///
    /// Never serialized. This is operator-authored free text, mandatory on `dataset hide`
    /// and `take-down`, and its own help calls it "a governance audit trail". That wording
    /// invites the specific strings that make it sensitive ("takedown requested by data
    /// subject `<isikukood>` via legal", "withdrawn consent, participant `<name>`"). It is
    /// personal data about the person the withholding is for.
    ///
    /// It stays in the three places that need it — the override file, the `dataset_suppressed`
    /// audit event, and the human `dataset list` table, which reads this field directly rather
    /// than through serde. It leaves neither JSON surface: not `GET /datasets` (the management
    /// plane has no authentication, so anything that reaches the port would read every
    /// justification the node holds in one request) and not `dataset list --format json` (a
    /// script piping these around is how the text escapes the node at all).
    ///
    /// `skip_serializing`, not `skip`: the field is still constructed and rendered, just never
    /// written to a wire.
    #[serde(skip_serializing)]
    pub reason: Option<String>,
    /// What the persisted status index declared, present only when an override has masked
    /// it (so `state != source_state`) and absent, not `null`, otherwise, mirroring
    /// [`Self::suppressed`]'s omission convention.
    ///
    /// Without this, composing the override into [`Self::state`] would destroy a fact the
    /// raw index carries: an `error` dataset that is also withheld would report only
    /// `hidden`, and an operator triaging failures would lose it. Appended last so the
    /// documented key order of the other fields is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_state: Option<DatasetState>,
}

/// Placeholder rows for every suppression-override id the status index has no
/// entry for. A `Remove`'s erase purges the status entry once complete, but the
/// override itself stays active (it keeps the anti-undo re-ingest gate armed), so
/// without this the id would silently vanish from the operator's inventory even
/// though it is still actively suppressed. The real record is gone, so
/// channel/provenance are placeholders (`GET /datasets/{id}/state` 404s for these —
/// this listing, not `/state`, is the inventory of what's suppressed).
///
/// Pure (no I/O beyond what the caller already loaded); unit-tested directly.
fn synthesize_missing_rows(
    index: &StatusIndex,
    overrides: &SuppressionSet,
) -> Vec<(String, StatusEntry)> {
    overrides
        .ids()
        .filter(|id| !index.entries().contains_key(*id))
        .map(|id| {
            (
                id.to_owned(),
                StatusEntry {
                    state: DatasetState::Hidden,
                    error_message: None,
                    channel: "unknown".to_owned(),
                    last_seen_signature: None,
                    provenance: DatasetProvenance::Unknown,
                },
            )
        })
        .collect()
}

/// Load the status index, apply `filter`, and print the result to stdout.
///
/// Read-only and lock-free (see the module doc). Exits `Ok` even when nothing matches —
/// an empty result is a valid answer, not an error.
///
/// # Errors
///
/// Returns an error if `filter` carries an unrecognized value, or if `.status.json`
/// exists but cannot be read or parsed. A missing index file is treated as empty.
pub fn run(config: &ServiceConfig, filter: &DatasetsFilter, format: OutputFormat) -> Result<()> {
    print!("{}", run_rendered(config, filter, format)?);
    Ok(())
}

/// [`run`]'s full pipeline (load, synthesize, filter, render), returning the rendered
/// output instead of printing it. Tests call through this seam so they exercise the same
/// disk-loading, synthesis-gating and filter logic `run` ships, rather than a hand-copied
/// re-implementation of the `chain`/`filter` pipeline.
fn run_rendered(
    config: &ServiceConfig,
    filter: &DatasetsFilter,
    format: OutputFormat,
) -> Result<String> {
    // A one-shot command has no live snapshot: the file it read is the configuration.
    Ok(render(
        &collect(config, filter, &Reloadable::from_config(config))?,
        format,
    ))
}

/// Load the status index + override store, apply `filter`, and return the matching rows.
///
/// The typed core both callers share: the `dataset list` CLI renders it, and the management
/// plane's `GET /datasets` serializes it. Returning rendered text instead would leave a
/// second consumer to re-implement the load, synthesis and filter pipeline or scrape a
/// table, and the two answers would drift invisibly until an operator and an integrating
/// system disagreed about what the node serves.
///
/// Read-only and lock-free (see the module doc). An empty result is a valid answer.
///
/// `reloadable` is the declared channel set the orphan rule composes over
/// ([`crate::state::channel_is_orphaned`]). The running node passes its live snapshot
/// (`AppState::reloadable`), so a bucket a reload added is declared here as it is for the
/// serving path; a one-shot CLI passes `Reloadable::from_config` over the file it read.
///
/// # Errors
///
/// Returns an error if `filter` carries an unrecognized value, or if `.status.json` exists
/// but cannot be read or parsed. A missing index file is treated as empty. An unreadable
/// override store is an error too, never an empty set; see the inline note below.
pub fn collect(
    config: &ServiceConfig,
    filter: &DatasetsFilter,
    reloadable: &Reloadable,
) -> Result<Vec<ListedDataset>> {
    filter.validate()?;
    let path = config.service.data_dir.join(".status.json");
    let index = StatusIndex::load(&path)
        .with_context(|| format!("loading status index {}", path.display()))?;
    // The suppressions store is a separate, fail-closed load (see the module doc). A
    // missing directory, meaning no override feature is in use, is an empty set. Unreadable
    // is not that case: this is a one-shot command with no last-good set, so adopting the
    // empty set would print an empty `--suppressed` inventory against an EACCES store,
    // telling the operator nothing is withheld when the withholds could not be read.
    let overrides = suppression::load_or_report(&suppression::suppressions_subdir(
        &config.service.override_dir_resolved(),
    ))
    .context("reading the override store to resolve which datasets are withheld")?;
    // Synthesize the erased-suppression placeholder rows only when the operator asked for
    // the suppressed inventory (`--suppressed`). A `Remove` suppression's erase purges the
    // status entry but keeps the override active (see `synthesize_missing_rows`'s doc), and
    // chaining these fabricated `state: Hidden, channel: "unknown"` rows in unconditionally
    // would leak an erased, GDPR-completed dataset into the plain listing, and into
    // `--state hidden`, as merely "hidden".
    let synthetic = if filter.suppressed {
        synthesize_missing_rows(&index, &overrides)
    } else {
        Vec::new()
    };

    // The orphan axis of the composition: a bucket channel the configuration does not
    // declare is withheld by the serve path's hydrate projection (cache-only, like a
    // suppression), and that withhold is in neither store this lock-free listing reads.
    // Composing it from the one predicate, over the same channel set the projection reads,
    // keeps this surface agreeing with the serving path and the oracle. Reporting the index
    // value raw here would report an orphan as visible while the node withholds it.
    let orphaned = |channel: &str| crate::state::channel_is_orphaned(reloadable, channel);

    // `entries()` is a `BTreeMap`, so iteration is already id-sorted — and ids embed a
    // creation timestamp, so id order is chronological order. The synthetic rows are
    // appended after: they have no status entry to sort by.
    let rows: Vec<ListedDataset> = index
        .entries()
        .iter()
        .map(|(id, entry)| (id.as_str(), entry))
        .chain(synthetic.iter().map(|(id, entry)| (id.as_str(), entry)))
        .filter_map(|(id, entry)| {
            let suppression = overrides.effective_full(id, &entry.channel);
            let withheld = suppression.is_some() || orphaned(&entry.channel);
            let effective = compose_state(entry.state, withheld);
            filter
                .matches(id, entry, effective, withheld)
                .then(|| ListedDataset::new(id, entry, suppression, effective))
        })
        .collect();

    Ok(rows)
}

impl ListedDataset {
    /// Project one index entry (plus its resolved override, if any) into a listed row.
    /// `effective` is the composed state from [`compose_state`]; it is passed in rather
    /// than recomputed, so the row that is filtered and the row that is printed cannot be
    /// judged against two different values.
    fn new(
        id: &str,
        entry: &StatusEntry,
        suppression: Option<&Suppression>,
        effective: DatasetState,
    ) -> Self {
        Self {
            id: id.to_owned(),
            state: effective,
            channel: entry.channel.clone(),
            provenance: entry.provenance.clone(),
            suppressed: suppression.map(|s| s.mode.as_str()),
            reason: suppression.map(|s| s.reason.clone()),
            source_state: (effective != entry.state).then_some(entry.state),
        }
    }
}

/// Render the matched rows in the requested format. Pure (no I/O), so it is unit-tested
/// directly. Always ends with a trailing newline (or is empty for an empty JSON array's
/// pretty form, which still ends in a newline).
fn render(rows: &[ListedDataset], format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => {
            // Pretty for human diff-ability; a list tool's output is read as often as piped.
            let mut s = serde_json::to_string_pretty(rows).unwrap_or_else(|_| "[]".to_owned());
            s.push('\n');
            s
        }
        OutputFormat::Text => render_table(rows),
    }
}

/// Shorten a `sha256:<64 hex>` fingerprint to `sha256:<12 hex>…` for the human table; the
/// full value is available via `--format json`.
fn short_fingerprint(fp: &str) -> String {
    match fp.strip_prefix("sha256:") {
        // `chars`, not bytes: `len() > 12` counts bytes and `&hex[..12]` slices bytes, so
        // a fingerprint carrying a multibyte character, which this renders because it prints
        // whatever the store handed back, could split a char boundary and panic while
        // formatting a list.
        Some(hex) if hex.chars().count() > 12 => {
            let short: String = hex.chars().take(12).collect();
            format!("sha256:{short}...")
        }
        _ => fp.to_owned(),
    }
}

/// The human-readable aligned table. Fixed leading columns are padded to their widest
/// value; the trailing writer-keys column is left ragged (no point padding the last one).
fn render_table(rows: &[ListedDataset]) -> String {
    use std::fmt::Write as _;

    // Precompute each row's cells so widths and output agree. Column order: `ID`, `STATE`,
    // `CHANNEL`, `PROVENANCE`, `SUPPRESSED`, a bounded `REASON`, and a ragged
    // `WRITER-KEYS` last.
    let cells: Vec<(&str, &str, &str, &str, &str, String, String)> = rows
        .iter()
        .map(|row| {
            let writers = row.provenance.fingerprints();
            let keys = if writers.is_empty() {
                "-".to_owned()
            } else {
                writers
                    .iter()
                    .map(|fp| short_fingerprint(fp))
                    .collect::<Vec<_>>()
                    .join(",")
            };
            (
                row.id.as_str(),
                row.state.as_str(),
                row.channel.as_str(),
                row.provenance.kind(),
                row.suppressed.unwrap_or("-"),
                row.reason
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), |r| truncate_reason(r)),
                keys,
            )
        })
        .collect();

    let headers = (
        "ID",
        "STATE",
        "CHANNEL",
        "PROVENANCE",
        "SUPPRESSED",
        "REASON",
        "WRITER KEYS",
    );
    let w_id = cells
        .iter()
        .map(|c| c.0.len())
        .chain([headers.0.len()])
        .max()
        .unwrap_or(0);
    let w_state = cells
        .iter()
        .map(|c| c.1.len())
        .chain([headers.1.len()])
        .max()
        .unwrap_or(0);
    let w_chan = cells
        .iter()
        .map(|c| c.2.len())
        .chain([headers.2.len()])
        .max()
        .unwrap_or(0);
    let w_prov = cells
        .iter()
        .map(|c| c.3.len())
        .chain([headers.3.len()])
        .max()
        .unwrap_or(0);
    let w_supp = cells
        .iter()
        .map(|c| c.4.len())
        .chain([headers.4.len()])
        .max()
        .unwrap_or(0);
    let w_reason = cells
        .iter()
        .map(|c| c.5.len())
        .chain([headers.5.len()])
        .max()
        .unwrap_or(0);

    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<w_id$}  {:<w_state$}  {:<w_chan$}  {:<w_prov$}  {:<w_supp$}  {:<w_reason$}  {}",
        headers.0, headers.1, headers.2, headers.3, headers.4, headers.5, headers.6
    );
    for (id, state, chan, prov, supp, reason, keys) in &cells {
        let _ = writeln!(
            out,
            "{id:<w_id$}  {state:<w_state$}  {chan:<w_chan$}  {prov:<w_prov$}  {supp:<w_supp$}  {reason:<w_reason$}  {keys}"
        );
    }
    out
}

/// Bound a suppression reason to a fixed width for the human table, so a long justification
/// cannot blow out the column.
///
/// The full reason is not available in `--format json`: [`ListedDataset::reason`] carries
/// `#[serde(skip_serializing)]` because that JSON is also the body of `GET /datasets`, and a
/// justification is personal data about the person the withholding is for. Read it from the
/// override file or the `dataset_suppressed` audit event.
fn truncate_reason(reason: &str) -> String {
    const MAX: usize = 32;
    let clean: String = reason.chars().filter(|c| !c.is_control()).collect();
    if clean.chars().count() > MAX {
        let head: String = clean.chars().take(MAX - 1).collect();
        format!("{head}...")
    } else if clean.is_empty() {
        "-".to_owned()
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use gdi_node_standalone_core::suppression::SuppressMode;

    fn entry(state: DatasetState, channel: &str, provenance: DatasetProvenance) -> StatusEntry {
        StatusEntry {
            state,
            error_message: None,
            channel: channel.to_owned(),
            last_seen_signature: None,
            provenance,
        }
    }

    fn recovered(fp: &str) -> DatasetProvenance {
        DatasetProvenance::Recovered {
            fingerprints: vec![fp.to_owned()],
        }
    }

    fn sample() -> Vec<(String, StatusEntry)> {
        vec![
            (
                "GDI-EE-1".to_owned(),
                entry(
                    DatasetState::Visible,
                    "egv-bucket",
                    recovered("sha256:aaaa"),
                ),
            ),
            (
                "GDI-EE-2".to_owned(),
                entry(DatasetState::Hidden, "inbox", DatasetProvenance::Plaintext),
            ),
            (
                "GDI-LV-3".to_owned(),
                entry(
                    DatasetState::Error,
                    "egv-bucket",
                    DatasetProvenance::RecoveryFailed,
                ),
            ),
            (
                "GDI-LV-4".to_owned(),
                entry(DatasetState::Visible, "inbox", DatasetProvenance::Unknown),
            ),
        ]
    }

    fn matching_ids(filter: &DatasetsFilter) -> Vec<String> {
        matching_ids_with(filter, |_id| None)
    }

    /// A stub suppression record carrying only the mode (reason/at are irrelevant to the
    /// filter, which only checks presence).
    fn supp(mode: SuppressMode) -> Suppression {
        Suppression {
            mode,
            reason: "test".to_owned(),
            at: String::new(),
        }
    }

    /// Like [`matching_ids`], but with a caller-supplied per-id suppression resolver —
    /// for exercising the `--suppressed` axis without a real suppressions store on disk.
    fn matching_ids_with(
        filter: &DatasetsFilter,
        suppressed: impl Fn(&str) -> Option<Suppression>,
    ) -> Vec<String> {
        sample()
            .iter()
            .filter(|(id, e)| {
                let s = suppressed(id);
                filter.matches(id, e, compose_state(e.state, s.is_some()), s.is_some())
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    #[test]
    fn empty_filter_matches_everything() {
        assert_eq!(matching_ids(&DatasetsFilter::default()).len(), 4);
    }

    #[test]
    fn state_filter_is_or_within_itself() {
        let filter = DatasetsFilter {
            states: vec!["error".to_owned(), "hidden".to_owned()],
            ..Default::default()
        };
        assert_eq!(matching_ids(&filter), ["GDI-EE-2", "GDI-LV-3"]);
    }

    #[test]
    fn channel_filter_is_exact() {
        let filter = DatasetsFilter {
            channel: Some("egv-bucket".to_owned()),
            ..Default::default()
        };
        assert_eq!(matching_ids(&filter), ["GDI-EE-1", "GDI-LV-3"]);
    }

    #[test]
    fn provenance_and_unverified_distinguish_the_no_fingerprint_cases() {
        let failed = DatasetsFilter {
            provenance: Some("recovery_failed".to_owned()),
            ..Default::default()
        };
        assert_eq!(matching_ids(&failed), ["GDI-LV-3"]);

        // `--unverified` is everything that is not `recovered`: the three keyless cases,
        // which is the collapse the enum exists to keep expressible.
        let unverified = DatasetsFilter {
            unverified: true,
            ..Default::default()
        };
        assert_eq!(
            matching_ids(&unverified),
            ["GDI-EE-2", "GDI-LV-3", "GDI-LV-4"]
        );
    }

    #[test]
    fn writer_filter_is_a_substring_over_recovered_fingerprints() {
        let filter = DatasetsFilter {
            writer: Some("aaaa".to_owned()),
            ..Default::default()
        };
        assert_eq!(matching_ids(&filter), ["GDI-EE-1"]);
        // A non-recovered dataset has no fingerprints, so it never matches a writer filter.
        let miss = DatasetsFilter {
            writer: Some("zzzz".to_owned()),
            ..Default::default()
        };
        assert!(matching_ids(&miss).is_empty());
    }

    #[test]
    fn id_substring_filters() {
        let filter = DatasetsFilter {
            id_substring: Some("LV".to_owned()),
            ..Default::default()
        };
        assert_eq!(matching_ids(&filter), ["GDI-LV-3", "GDI-LV-4"]);
    }

    #[test]
    fn predicates_are_anded() {
        let filter = DatasetsFilter {
            states: vec!["visible".to_owned()],
            channel: Some("inbox".to_owned()),
            ..Default::default()
        };
        assert_eq!(matching_ids(&filter), ["GDI-LV-4"]);
    }

    #[test]
    fn suppressed_filter_keeps_only_overridden_datasets() {
        let filter = DatasetsFilter {
            suppressed: true,
            ..Default::default()
        };
        // Only GDI-EE-2 (hide) and GDI-LV-3 (remove) carry an override; the other two
        // resolve to `None` from the (stubbed) suppression resolver.
        let ids = matching_ids_with(&filter, |id| match id {
            "GDI-EE-2" => Some(supp(SuppressMode::Hide)),
            "GDI-LV-3" => Some(supp(SuppressMode::Remove)),
            _ => None,
        });
        assert_eq!(ids, ["GDI-EE-2", "GDI-LV-3"]);
    }

    #[test]
    fn suppressed_filter_off_is_unaffected_by_a_present_override() {
        // The default (`suppressed: false`) must not filter at all, even when an id
        // happens to carry an override — `--suppressed` is opt-in narrowing, not an
        // implicit exclusion of overridden datasets from the default listing.
        let ids = matching_ids_with(&DatasetsFilter::default(), |id| {
            (id == "GDI-EE-1").then(|| supp(SuppressMode::Hide))
        });
        assert_eq!(ids.len(), 4);
    }

    /// `--state` filters on what the node serves, not on what the index declares.
    ///
    /// `GDI-EE-1` is `visible` in the index and withheld by an override. Both halves are
    /// asserted: it must answer `--state hidden`, the query an operator runs to confirm a
    /// withhold took effect, and must not answer `--state visible`, which would read as
    /// "this is being served".
    #[test]
    fn state_filter_follows_the_withhold_not_the_index_value() {
        let hidden = DatasetsFilter {
            states: vec!["hidden".to_owned()],
            ..DatasetsFilter::default()
        };
        let ids = matching_ids_with(&hidden, |id| {
            (id == "GDI-EE-1").then(|| supp(SuppressMode::Hide))
        });
        assert!(
            ids.contains(&"GDI-EE-1".to_owned()),
            "a withheld dataset must answer --state hidden: {ids:?}"
        );

        let visible = DatasetsFilter {
            states: vec!["visible".to_owned()],
            ..DatasetsFilter::default()
        };
        let ids = matching_ids_with(&visible, |id| {
            (id == "GDI-EE-1").then(|| supp(SuppressMode::Hide))
        });
        assert!(
            !ids.contains(&"GDI-EE-1".to_owned()),
            "and must not still answer --state visible: {ids:?}"
        );
    }

    /// Composing the override must not swallow the health axis: `GDI-LV-3` is `error` in
    /// the index, and hiding it does not repair it. Without the carve-out in
    /// `state_matches`, `--errors` would quietly stop reporting exactly the datasets an
    /// operator withheld because they were broken.
    #[test]
    fn an_errored_dataset_still_answers_the_error_filter_after_a_withhold() {
        let filter = DatasetsFilter {
            states: vec!["error".to_owned()],
            ..DatasetsFilter::default()
        };
        let ids = matching_ids_with(&filter, |id| {
            (id == "GDI-LV-3").then(|| supp(SuppressMode::Hide))
        });
        assert!(
            ids.contains(&"GDI-LV-3".to_owned()),
            "a withheld dataset is still a broken one: {ids:?}"
        );
    }

    /// The masked index value survives on the row, and only when it was actually masked.
    #[test]
    fn source_state_appears_only_when_the_override_changed_the_answer() {
        let entry = entry(DatasetState::Error, "inbox", DatasetProvenance::Unknown);
        let s = supp(SuppressMode::Hide);

        let row = ListedDataset::new(
            "GDI-EE-1",
            &entry,
            Some(&s),
            compose_state(entry.state, true),
        );
        assert_eq!(row.state, DatasetState::Hidden);
        assert_eq!(row.source_state, Some(DatasetState::Error));
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["source_state"], "error");

        let row = ListedDataset::new("GDI-EE-1", &entry, None, entry.state);
        assert_eq!(
            row.source_state, None,
            "unmasked rows carry no second state"
        );
        let json = serde_json::to_value(&row).unwrap();
        assert!(
            json.get("source_state").is_none(),
            "and omit the key rather than emitting null: {json}"
        );
    }

    // Valid dataset-id shapes (`^(GOE|GDI)-[A-Z]{2}-[A-Z]+-[0-9]+$` — see `core::id`):
    // `suppression::load` skips anything else, unlike `sample()`'s ids (fed to
    // `DatasetsFilter::matches` directly, never through `suppression::load`).
    const PRESENT_ID: &str = "GDI-EE-UTARTU-20260409143052837";
    const ABSENT_ID: &str = "GDI-FI-THL-20260409143052838";

    #[test]
    fn synthesize_missing_rows_only_covers_override_ids_absent_from_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let sub = suppression::suppressions_subdir(dir.path());
        suppression::write_file(
            &sub,
            PRESENT_ID, // has a status entry below — must not be synthesized
            &suppression::Suppression {
                mode: SuppressMode::Hide,
                reason: "embargo".to_owned(),
                at: String::new(),
            },
        )
        .unwrap();
        suppression::write_file(
            &sub,
            ABSENT_ID, // no status entry — a take-down whose erase already purged it
            &suppression::Suppression {
                mode: SuppressMode::Remove,
                reason: "erasure".to_owned(),
                at: String::new(),
            },
        )
        .unwrap();
        let overrides = suppression::load(&sub);

        let mut index = StatusIndex::new();
        index.insert(
            PRESENT_ID.to_owned(),
            entry(DatasetState::Hidden, "inbox", DatasetProvenance::Plaintext),
        );

        let synthetic = synthesize_missing_rows(&index, &overrides);
        assert_eq!(synthetic.len(), 1, "{synthetic:?}");
        assert_eq!(synthetic[0].0, ABSENT_ID);
    }

    #[test]
    fn suppressed_filter_includes_a_remove_id_with_no_status_entry() {
        // A `Remove` suppression outlives its status entry once the erase it triggers
        // purges that entry. The id must still surface in `dataset list --suppressed`, the
        // operator's only remaining view of it.
        let dir = tempfile::tempdir().unwrap();
        let sub = suppression::suppressions_subdir(dir.path());
        suppression::write_file(
            &sub,
            ABSENT_ID,
            &suppression::Suppression {
                mode: SuppressMode::Remove,
                reason: "erasure".to_owned(),
                at: String::new(),
            },
        )
        .unwrap();
        let overrides = suppression::load(&sub);
        let index = StatusIndex::new(); // no status entry at all for this id

        let synthetic = synthesize_missing_rows(&index, &overrides);
        let filter = DatasetsFilter {
            suppressed: true,
            ..Default::default()
        };
        let rows: Vec<ListedDataset> = index
            .entries()
            .iter()
            .map(|(id, e)| (id.as_str(), e))
            .chain(synthetic.iter().map(|(id, e)| (id.as_str(), e)))
            .filter_map(|(id, e)| {
                let s = overrides.effective_full(id, &e.channel);
                let eff = compose_state(e.state, s.is_some());
                filter
                    .matches(id, e, eff, s.is_some())
                    .then(|| ListedDataset::new(id, e, s, eff))
            })
            .collect();

        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].id, ABSENT_ID);
        assert_eq!(rows[0].suppressed, Some("remove"), "mode=remove");
        assert_eq!(
            rows[0].reason.as_deref(),
            Some("erasure"),
            "reason surfaced"
        );
    }

    fn config_with_dirs(
        data_dir: &std::path::Path,
        override_dir: &std::path::Path,
    ) -> ServiceConfig {
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
            override_dir.display(),
        );
        ServiceConfig::from_toml_str(&toml).unwrap()
    }

    /// Exercised through [`run_rendered`], `run`'s own pipeline rather than a
    /// re-implementation of it. A `Remove`-suppressed id with no status entry, its erase
    /// having already purged it (see `synthesize_missing_rows`'s doc), is absent from the
    /// plain `dataset list` output and present once `--suppressed` is passed. A missing
    /// `.status.json` loads as an empty index (see `run`'s doc), so only the suppression
    /// override file is needed.
    #[test]
    fn plain_listing_excludes_an_erased_remove_suppression_but_suppressed_includes_it() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let override_dir = dir.path().join("overrides");
        let sub = suppression::suppressions_subdir(&override_dir);
        suppression::write_file(
            &sub,
            ABSENT_ID,
            &suppression::Suppression {
                mode: SuppressMode::Remove,
                reason: "erasure".to_owned(),
                at: String::new(),
            },
        )
        .unwrap();
        let config = config_with_dirs(&data_dir, &override_dir);

        let plain = run_rendered(&config, &DatasetsFilter::default(), OutputFormat::Json).unwrap();
        assert!(
            !plain.contains(ABSENT_ID),
            "plain `dataset list` must not fabricate a row for an erased Remove \
             suppression: {plain}"
        );

        let suppressed_filter = DatasetsFilter {
            suppressed: true,
            ..Default::default()
        };
        let suppressed = run_rendered(&config, &suppressed_filter, OutputFormat::Json).unwrap();
        assert!(
            suppressed.contains(ABSENT_ID),
            "`dataset list --suppressed` must still surface the erased Remove \
             suppression as the operator's only remaining view of it: {suppressed}"
        );
    }

    #[test]
    fn validate_rejects_unknown_state_and_provenance() {
        assert!(
            DatasetsFilter {
                states: vec!["visable".to_owned()],
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            DatasetsFilter {
                provenance: Some("recoverd".to_owned()),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(DatasetsFilter::default().validate().is_ok());
    }

    /// `sample()` rows with no suppression override on any of them, for tests that
    /// exercise the state/channel/provenance/writer-keys columns and don't care about
    /// the suppression axis.
    fn rows_unsuppressed(data: &[(String, StatusEntry)]) -> Vec<ListedDataset> {
        data.iter()
            .map(|(id, e)| ListedDataset::new(id, e, None, e.state))
            .collect()
    }

    /// Attach a suppression to one already-built row, as `collect` would have — including
    /// the override composition, so the row's `state` becomes `hidden` and its pre-existing
    /// state moves to `source_state` exactly as it does in production.
    fn suppress(row: &mut ListedDataset, s: &Suppression) {
        let entry = StatusEntry {
            state: row.state,
            error_message: None,
            channel: row.channel.clone(),
            last_seen_signature: None,
            provenance: row.provenance.clone(),
        };
        let with = ListedDataset::new(&row.id, &entry, Some(s), compose_state(entry.state, true));
        *row = with;
    }

    #[test]
    fn json_output_is_an_array_carrying_the_tagged_provenance() {
        let data = sample();
        let rows = rows_unsuppressed(&data);
        let json: serde_json::Value =
            serde_json::from_str(&render(&rows, OutputFormat::Json)).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 4);
        assert_eq!(json[0]["id"], "GDI-EE-1");
        assert_eq!(json[0]["state"], "visible");
        assert_eq!(json[0]["provenance"]["kind"], "recovered");
        assert_eq!(json[2]["provenance"]["kind"], "recovery_failed");
        // Unsuppressed: the field is omitted rather than `null`, mirroring the oracle's
        // `suppression` field (`datasets_http::StateBody`).
        assert!(json[0].get("suppressed").is_none(), "{json}");
    }

    #[test]
    fn json_output_carries_the_suppression_mode_but_never_the_reason() {
        let data = sample();
        let mut rows = rows_unsuppressed(&data);
        let s = Suppression {
            mode: SuppressMode::Remove,
            // The test needs only the shape of person-identifying text, so the personal
            // ID code below is invalid on two independent grounds and must stay that way:
            // month `13` cannot exist, and the check digit is wrong (the mod-11 weighting
            // of `3991331999` yields 1, not 0). A valid code may belong to a real person
            // and must never be committed. Two grounds rather than one, because a
            // checksum-only fixture invites a later "typo fix" that turns it into a real
            // person's code, while an impossible month cannot be repaired by correcting a
            // digit.
            reason: "erasure requested by data subject 39913319990 via legal".to_owned(),
            at: String::new(),
        };
        suppress(&mut rows[1], &s); // GDI-EE-2
        let rendered = render(&rows, OutputFormat::Json);
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(json[1]["id"], "GDI-EE-2");
        assert_eq!(json[1]["suppressed"], "remove");
        // The mode travels, the justification does not. This JSON is both
        // `dataset list --format json` and the body of `GET /datasets` on an unauthenticated
        // management plane, so a justification here is one request away from anything that
        // can reach the port, and it is personal data about the person the withholding is
        // for. Asserted on the substring rather than the field, so a rename cannot smuggle
        // it through.
        assert!(
            json[1].get("reason").is_none(),
            "the justification must not be serialized: {rendered}"
        );
        assert!(
            !rendered.contains("39913319990"),
            "no part of the justification may reach the wire: {rendered}"
        );
    }

    #[test]
    fn text_table_shows_the_suppression_reason_column() {
        let data = sample();
        let mut rows = rows_unsuppressed(&data);
        let s = Suppression {
            mode: SuppressMode::Hide,
            reason: "embargo until 2027".to_owned(),
            at: String::new(),
        };
        suppress(&mut rows[1], &s);
        let text = render(&rows, OutputFormat::Text);
        assert!(
            text.lines().next().unwrap().contains("REASON"),
            "header has REASON"
        );
        assert!(
            text.contains("embargo until 2027"),
            "the suppression reason must be shown in the table: {text}"
        );
    }

    #[test]
    fn text_output_has_a_header_and_one_line_per_dataset() {
        let data = sample();
        let rows = rows_unsuppressed(&data);
        let text = render(&rows, OutputFormat::Text);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 5, "header + 4 rows");
        assert!(lines[0].starts_with("ID"));
        assert!(lines[0].contains("SUPPRESSED"), "header: {}", lines[0]);
        assert!(lines[1].contains("GDI-EE-1"));
        assert!(lines[1].contains("recovered"));
        // An unsuppressed row shows `-` in the `SUPPRESSED` column.
        assert!(
            lines[1].contains(" - "),
            "unsuppressed row shows a dash placeholder: {}",
            lines[1]
        );
        // A keyless dataset shows `-` in the writer-keys column.
        assert!(
            lines[2].trim_end().ends_with('-'),
            "plaintext row: {}",
            lines[2]
        );
    }

    #[test]
    fn text_output_shows_the_suppression_mode_in_its_own_column() {
        let data = sample();
        let mut rows = rows_unsuppressed(&data);
        let s = supp(SuppressMode::Hide);
        suppress(&mut rows[2], &s); // GDI-LV-3
        let text = render(&rows, OutputFormat::Text);
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[3].contains("GDI-LV-3"));
        assert!(lines[3].contains("hide"), "row: {}", lines[3]);
    }

    #[test]
    fn empty_result_still_renders_a_header_in_text_and_a_list_in_json() {
        assert!(render(&[], OutputFormat::Text).starts_with("ID"));
        assert_eq!(render(&[], OutputFormat::Json).trim(), "[]");
    }
}
