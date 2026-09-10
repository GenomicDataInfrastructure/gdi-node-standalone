//! Store scrub: validate dataset directories against the loaded key material. Checks footer
//! readability, and optionally full parquet validation and at-rest digest verification.
//!
//! Shared by the startup self-test (a bounded sample on the critical path plus a detached
//! full sweep) and the offline `verify` subcommand. A footer probe costs about one Vault DEK
//! fetch per parquet file under PME, so a full sweep is bounded wall-clock rather than a
//! Vault burst. It must still stay off the readiness-gating critical path, which is why the
//! boot self-test only samples.

use std::path::Path;
use std::sync::atomic::Ordering;

use gdi_node_standalone_core::digest::{DigestVerdict, verify_parquet_digests};
use gdi_node_standalone_core::error::CoreError;
use gdi_node_standalone_core::parquet_io::probe_dataset_readable;
use gdi_node_standalone_core::s3_layout::is_data_file_name;
use gdi_node_standalone_core::validate_parquet::validate_parquet_dir;

use crate::state::AppState;

/// How deep a per-dataset scrub goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrubDepth {
    /// Open every parquet footer with the loaded key material (PME-aware), proving the key
    /// reads the store. Cheap: no full decode, ~1 Vault DEK per parquet file under PME.
    Footer,
    /// Footer plus full parquet schema/value/uniqueness validation. Plaintext stores only; a
    /// PME store falls back to footer-only, because offline full-decode of `PARE` is not
    /// supported here.
    Full,
    /// Footer plus verification of the at-rest digest sidecar, and nothing else. This is the
    /// bit-rot tier: `parquet-digests.json`, written at ingest from the stored bytes, already
    /// answers "did a byte change?", so re-running row validation here would repeat
    /// ingest-time work for no extra detection at orders of magnitude more cost (see
    /// `docs/operating.md` §2). Plaintext stores only, falling back to footer-only on a PME
    /// store like `Full`. A missing sidecar on a plaintext store fails closed as a tamper
    /// signal, never a green "unverified".
    Digest,
    /// [`Self::Full`] and [`Self::Digest`] together: the offline `verify --full --digest`.
    /// Not used by the online sweep, which cannot afford the row validation every pass.
    FullDigest,
}

/// One dataset's scrub result.
pub struct ScrubResult {
    /// The dataset id.
    pub id: String,
    /// Whether the dataset passed at the requested depth.
    pub ok: bool,
    /// Whether a `!ok` verdict is a transient fault rather than a finding about the data.
    ///
    /// Always `false` when `ok`. A transient failure is reported and counted, but must not
    /// quarantine: withholding a dataset because one `read_dir` returned `EIO` turns a blip
    /// into an operator-action outage.
    pub transient: bool,
    /// A short human-readable detail (the pass note, or the failure cause).
    pub detail: String,
}

/// The at-rest form of one stored dataset, from the 4-byte parquet magic of its first
/// data file.
///
/// Not a `bool`: a predicate like `!is_plaintext_store` is `false` for four different worlds
/// (a `PARE` store, a directory holding no `allele-freq.*.parquet`, one truncated below its
/// magic, and one that cannot be read at all), so negating it reports a missing, corrupt or
/// unreadable store as PME-encrypted at every consumer. Naming each case in the type leaves
/// no `bool` to negate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtRestForm {
    /// A `PAR1` (plaintext) parquet: the only form that supports offline full-decode
    /// validation and digest verification.
    Plaintext,
    /// A `PARE` (PME-encrypted) parquet.
    Encrypted,
    /// Neither: no `allele-freq.*.parquet` at all, or one truncated below its 4-byte magic.
    /// For a published dataset this is corruption, not an at-rest form. Ingest publishes by
    /// atomic rename, so a directory the cache holds is a complete one.
    Indeterminate,
    /// The question could not be answered: the directory or its first data file could not
    /// be read (EACCES, EIO, ESTALE, EMFILE, …).
    ///
    /// Distinct from [`Self::Indeterminate`] because the two demand opposite handling. A
    /// dataset whose parquet is gone is corrupt and must be withheld; one the node merely
    /// could not read right now is a transient fault on a live dataset, and quarantining it
    /// converts an fd-exhaustion blip or an NFS stall into an outage needing operator
    /// action.
    Unreadable,
}

/// Read one dataset directory's [`AtRestForm`]. Reads only the 4-byte magic of one file.
///
/// The single definition every consumer shares: `doctor`'s posture line, the
/// `gdi_datasets_at_rest` gauge, the scrub depth gate, and `pme reseal`'s artifact pick. They
/// cannot drift into disagreeing about what the store holds.
pub(crate) fn at_rest_form(dir: &Path) -> AtRestForm {
    match first_data_file_magic(dir) {
        Ok(Some(magic)) if &magic == b"PAR1" => AtRestForm::Plaintext,
        Ok(Some(magic)) if &magic == b"PARE" => AtRestForm::Encrypted,
        // Read fine, but not a form this build serves: an unrecognised magic, a directory
        // with no data file, or one truncated below four bytes.
        Ok(_) => AtRestForm::Indeterminate,
        // A dataset directory that is gone is loss, not an unreadable fault: the cache
        // holds an id whose store vanished, which is the corruption the Indeterminate arm
        // exists to withhold. Only the faults that say nothing about the data are
        // transient.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => AtRestForm::Indeterminate,
        Err(_) => AtRestForm::Unreadable,
    }
}

/// The 4-byte parquet magic of the first data file in `dir`.
///
/// The single read [`at_rest_form`] classifies. Three outcomes: `Ok(Some(magic))` read it,
/// `Ok(None)` there is nothing to read (no data file, or one shorter than the magic, both
/// damage to a published dataset), and `Err` could not tell (an I/O fault that says nothing
/// about the data).
///
/// # Errors
///
/// Returns the underlying [`std::io::Error`] when the directory cannot be enumerated or the
/// first data file cannot be opened or read.
fn first_data_file_magic(dir: &Path) -> std::io::Result<Option<[u8; 4]>> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if is_data_file_name(name) {
            use std::io::Read as _;
            let mut magic = [0u8; 4];
            let mut f = std::fs::File::open(entry.path())?;
            return match f.read_exact(&mut magic) {
                Ok(()) => Ok(Some(magic)),
                // The file is there and is too short: damage, not an I/O fault.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
                Err(e) => Err(e),
            };
        }
    }
    Ok(None)
}

/// Scrub one dataset to `depth`. Never panics; any failure becomes a non-`ok`
/// [`ScrubResult`] rather than an error or abort.
#[must_use]
pub fn scrub_dataset(state: &AppState, id: &str, depth: ScrubDepth) -> ScrubResult {
    let dir = state.config.service.data_dir.join(id);
    let ok = |detail: &str| ScrubResult {
        id: id.to_owned(),
        ok: true,
        transient: false,
        detail: detail.to_owned(),
    };
    let fail = |detail: String| ScrubResult {
        id: id.to_owned(),
        ok: false,
        transient: false,
        detail,
    };
    // A `!ok` the node cannot attribute to the data. Reported and counted like any other
    // failure, but never quarantined.
    let fail_transient = |detail: String| ScrubResult {
        id: id.to_owned(),
        ok: false,
        transient: true,
        detail,
    };

    // Manifest first: a small JSON read is far cheaper than a footer decrypt.
    //
    // A stored `manifest.json` that will not parse takes the dataset out of serving:
    // `cache::apply_scan` skips it on every reload, so Beacon, the `datasets` listing and
    // the FDP all drop it. Recording that as a fault is what stops `GET /datasets/{id}/state`
    // answering `visible` for a dataset the node no longer serves, and what lets the
    // documented recovery (`deploy --replace`) proceed instead of being refused because the
    // id still reads as live. operating.md §1 promises "the next sweep quarantines the
    // dataset and releases both", for the manifest class as well as the parquet one.
    //
    // Classified like every other check here: unparseable is attributable to the data
    // (quarantine), an I/O fault is not (count, keep serving). A missing manifest stays
    // silent, as in `cache.rs`, because ingest writes it last via temp+rename and a delete
    // may be mid-flight.
    let manifest_path = dir.join("manifest.json");
    match std::fs::read(&manifest_path) {
        Ok(raw) => {
            if let Err(e) =
                serde_json::from_slice::<gdi_node_standalone_core::model::Manifest>(&raw)
            {
                return fail(format!(
                    "manifest.json does not parse, so this dataset is skipped on every cache \
                     reload and is not served: {e}"
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return fail_transient(format!("manifest.json unreadable: {e}")),
    }

    // Footer (always): PME-aware readability with the loaded key material.
    //
    // This is the one scrub step that talks to Vault, and `core` keeps the transient class
    // intact across three layers for this decision (`vault_to_core` -> `CoreError::Transient`
    // -> `core_to_parquet` stamps the PME transient marker -> `classify_parquet_decode_error`
    // recovers it). Routing every failure through the non-transient `fail` would quarantine
    // every dataset touched by one Vault 429/503/timeout, a resource-exhaustion I/O error, or
    // a keyless-degraded boot, and a quarantine no operator action clears is worse than the
    // outage that caused it. `is_transient()` is the classifier the ingest path uses, so the
    // two cannot drift.
    if let Err(e) = probe_dataset_readable(&dir, &state.dataset_decryptor()) {
        return if e.is_transient() {
            fail_transient(format!("unreadable (transient): {e}"))
        } else {
            fail(format!("unreadable: {e}"))
        };
    }
    // Classified even at Footer: `Indeterminate` is not an at-rest form, it is "this
    // published dataset has no readable parquet at all", which is corruption. Footer is what
    // nearly everything runs (the sweep's per-pass tier, the boot self-test, bare `verify`),
    // and `probe_dataset_readable` returns `Ok` for an empty dataset directory.
    let form = at_rest_form(&dir);
    if form == AtRestForm::Indeterminate {
        return fail(
            "no readable parquet: the dataset directory holds no `allele-freq.*.parquet` \
             whose magic can be read (deleted or truncated)"
                .to_owned(),
        );
    }
    if form == AtRestForm::Unreadable {
        return fail_transient(
            "at-rest form unreadable: the dataset directory or its first parquet could not \
             be read (permissions, I/O error, or too many open files). This says nothing \
             about the data."
                .to_owned(),
        );
    }
    if depth == ScrubDepth::Footer {
        return ok("footer ok");
    }

    // Every depth past Footer needs a plaintext store (offline PARE full-decode
    // unsupported, and PME files carry their own per-segment AEAD tamper detection).
    match form {
        AtRestForm::Plaintext => {}
        AtRestForm::Encrypted => return ok("PME: footer-only"),
        // Both already returned above, before the Footer early-return. Kept as explicit arms
        // rather than a wildcard, so adding a further form is a compile error here too.
        AtRestForm::Indeterminate => return fail("no readable parquet".to_owned()),
        AtRestForm::Unreadable => {
            return fail_transient("at-rest form unreadable".to_owned());
        }
    }
    if matches!(depth, ScrubDepth::Full | ScrubDepth::FullDigest)
        && let Err(e) = validate_parquet_dir(&dir, &state.config.service.parquet_caps())
    {
        return fail(format!("invalid parquet: {e}"));
    }
    if depth == ScrubDepth::Full {
        return ok("full ok");
    }

    // Digest (`Digest` | `FullDigest`). Reached only for a plaintext store with at least one
    // `allele-freq.*.parquet`, since the PME and empty-directory cases returned above, and
    // every such store is written with a `parquet-digests.json` sidecar at ingest. A missing
    // sidecar (`Unverified`) here is therefore anomalous (a deleted sidecar, or tampering)
    // rather than the benign PME/legacy case, and must fail closed.
    match verify_parquet_digests(&dir) {
        Ok(DigestVerdict::Verified(n)) => ok(&format!("digest ok ({n})")),
        Ok(DigestVerdict::Unverified) => fail(
            "digest: no parquet-digests.json sidecar on a plaintext store (written at \
             ingest for every plaintext store; its absence indicates tampering or \
             corruption)"
                .to_owned(),
        ),
        Ok(DigestVerdict::Mismatch(f)) => fail(format!("digest mismatch: {f}")),
        // A sidecar that does not parse is a finding (`InvalidManifest`). An I/O error
        // opening or reading a listed file (permissions, too many open files, a read fault)
        // is not, exactly as the at-rest form probe above classifies it: routed through
        // `fail` it would quarantine a healthy dataset as tampered on an fd-limit blip.
        Err(e) if e.is_transient() || matches!(e, CoreError::Io(_)) => {
            fail_transient(format!("digest check I/O error (transient): {e}"))
        }
        Err(e) => fail(format!("digest check error: {e}")),
    }
}

/// The at-rest composition of a store: every dataset directory counted into exactly one
/// bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct AtRestTally {
    /// Stores whose parquet carries the `PAR1` magic.
    pub(crate) plaintext: u32,
    /// Stores whose parquet carries the `PARE` (PME) magic.
    pub(crate) encrypted: u32,
    /// Stores with no readable `allele-freq.*.parquet`. Its own bucket, never folded into
    /// `encrypted`: that fold would report a deleted or truncated parquet as at-rest
    /// encrypted in both `doctor` and the gauge.
    pub(crate) indeterminate: u32,
}

impl AtRestTally {
    /// Every dataset directory counted, in any form.
    pub(crate) const fn total(self) -> u32 {
        self.plaintext
            .saturating_add(self.encrypted)
            .saturating_add(self.indeterminate)
    }
}

/// Tally the at-rest composition of the store under `data_dir`.
///
/// A dataset store is a directory whose name is a valid dataset id, so `.status.json`, the
/// override dir and any other entry are skipped. Each is classified by [`at_rest_form`],
/// which reads only the 4-byte magic of one file per store.
///
/// `doctor` and the `gdi_datasets_at_rest` gauge both read this, so the on-demand check and
/// the standing signal cannot drift into disagreeing about what the store holds. An
/// unreadable `data_dir` (a fresh node) tallies all zeroes rather than failing, because the
/// absence of datasets is not a finding.
#[must_use]
pub(crate) fn at_rest_tally(data_dir: &Path) -> AtRestTally {
    let mut tally = AtRestTally::default();
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return tally;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !path.is_dir() || !gdi_node_standalone_core::id::is_valid_dataset_id(name) {
            continue;
        }
        match at_rest_form(&path) {
            AtRestForm::Plaintext => tally.plaintext += 1,
            AtRestForm::Encrypted => tally.encrypted += 1,
            // Both count as "not classifiable" for the composition gauge, which asks what
            // the store holds, not why a directory could not be read. The scrub path is
            // where the two diverge.
            AtRestForm::Indeterminate | AtRestForm::Unreadable => tally.indeterminate += 1,
        }
    }
    tally
}

/// Act on one failed [`ScrubResult`]: quarantine the dataset, unless the failure is
/// transient, in which case it stays served and only a warning records it.
///
/// The one place a scrub verdict becomes a quarantine. Routed through here so a new sweep
/// tier cannot reintroduce "withhold on any non-`ok`" by forgetting the transient check,
/// which turns an `EIO` on one `read_dir` into an operator-action outage.
fn act_on_scrub_failure(state: &AppState, r: &ScrubResult) {
    if r.transient {
        tracing::warn!(
            dataset = %r.id,
            detail = %r.detail,
            "store scrub could not classify a dataset; leaving it served (transient fault)"
        );
        return;
    }
    crate::ingest_runtime::quarantine_scrub_failure(state, &r.id, &r.detail);
}

/// One PME-encrypted (`PARE`) dataset store under `data_dir`, or `None` when the store holds
/// none (a fresh node, or an all-plaintext one).
///
/// Used by `pme reseal` to obtain a real, previously-written artifact to test the current
/// Transit key against before it may overwrite the at-rest sentinel. Built on the same
/// [`at_rest_form`] classification [`at_rest_tally`] uses, so the reseal proof cannot
/// disagree with the gauge that reports the store's composition. An
/// [`AtRestForm::Indeterminate`] directory is not a candidate: the reseal would then probe
/// zero files, succeed vacuously, and clear the sentinel latch without exercising the key.
///
/// Deterministic (first by sorted id) so a repeated reseal probes the same store.
#[must_use]
#[cfg(feature = "pme")]
pub(crate) fn first_encrypted_store(data_dir: &Path) -> Option<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return None;
    };
    let mut encrypted: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(gdi_node_standalone_core::id::is_valid_dataset_id)
                && at_rest_form(p) == AtRestForm::Encrypted
        })
        .collect();
    encrypted.sort();
    encrypted.into_iter().next()
}

/// How many datasets each sweep verifies at digest depth. A digest check rehashes whole
/// files, so a small slice bounds the per-pass cost while still giving every dataset periodic
/// at-rest verification (a 100-dataset node cycles in ~25 sweeps). Not a config knob: the
/// readability tier still covers every dataset every pass.
const DIGEST_PER_SWEEP: usize = 4;

/// Which sweep is running.
///
/// The boot pass is the immediate first tick after start. It skips the rotating digest slice,
/// so that `DIGEST_PER_SWEEP` whole-file rehashes do not land on every restart; a dataset it
/// skips is verified one `rescan_interval_seconds` later by the first periodic pass, and the
/// cursor is not advanced, so no slot is lost.
///
/// Deferred *per restart*: a node that restarts more often than `rescan_interval_seconds`
/// never reaches a periodic pass, so bit-rot detection latency becomes unbounded rather than
/// one interval. The alternative is minutes of CPU re-hashing on every restart, and the
/// readability tier still covers every dataset on every one of those boots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrubPass {
    /// The first sweep after start: the readability tier over every dataset, plus
    /// re-verification of the normally-empty persisted quarantined set. Not the rotating
    /// digest slice.
    Boot,
    /// Every later sweep: digest slice, quarantine re-check, readability.
    Periodic,
}

/// Scrub every cached dataset and **quarantine** (state → `Error`, evicted from the served
/// view) any that fails, returning the failure count.
///
/// Every dataset is checked at [`ScrubDepth::Footer`] on every pass, which catches
/// truncation, a wrong key and a corrupt footer, and the quarantined set is re-verified on
/// every pass too. The rotating digest slice is what a [`ScrubPass::Boot`] pass leaves out
/// and a [`ScrubPass::Periodic`] pass adds: `DIGEST_PER_SWEEP` datasets are additionally
/// checked at [`ScrubDepth::Digest`], the only tier that sees silent data-page bit-rot behind
/// an intact footer on a live node.
///
/// Factored out of the sweep task so it runs synchronously in a test and inside
/// `spawn_blocking` in the service. Also publishes the at-rest composition gauge under PME,
/// from the same shared tally `doctor` reads.
#[must_use]
pub fn run_scrub_sweep(state: &AppState, pass: ScrubPass) -> usize {
    let ids = state.cache.ids();
    let mut failed = 0usize;
    let mut checked: std::collections::HashSet<&str> = std::collections::HashSet::new();

    // Digest tier first, on a rotating slice. The readability sweep below opens each file's
    // footer, which catches truncation, a wrong key and a corrupt footer, but not silent
    // bit-rot in the page data; the offline `verify --digest` needs the exclusive data-dir
    // lock (§17), so it cannot run on a live node. The reference digests are already on disk
    // in `parquet-digests.json`, written at ingest.
    //
    // Rehashing whole files every pass would be far too expensive, so it is amortised: each
    // sweep verifies the next `DIGEST_PER_SWEEP` datasets and advances the cursor. A store
    // that fails here is quarantined exactly as a readability failure is.
    //
    // Skipped on the boot pass: the amortisation bounds only the steady-state cost, and the
    // first tick is immediate, so every restart would pay a rehash of four whole datasets
    // before the sweep reported anything. The cursor is untouched, so the slice is not lost.
    if pass == ScrubPass::Periodic && !ids.is_empty() {
        let start = state
            .digest_scrub_cursor
            .fetch_add(DIGEST_PER_SWEEP, Ordering::Relaxed);
        for offset in 0..DIGEST_PER_SWEEP.min(ids.len()) {
            let id = &ids[(start + offset) % ids.len()];
            // A quarantined dataset is re-verified at this same depth by the pass below,
            // which is also what counts it; scrubbing it here too would count it twice.
            if state.is_scrub_quarantined(id) {
                continue;
            }
            let r = scrub_dataset(state, id, ScrubDepth::Digest);
            checked.insert(id.as_str());
            if !r.ok {
                failed += 1;
                act_on_scrub_failure(state, &r);
            }
        }
    }

    failed += reverify_quarantined(state, &ids, &mut checked);

    for id in &ids {
        // Already verified at the deeper tier this pass; re-opening the footer would
        // only repeat work it subsumes.
        if checked.contains(id.as_str()) {
            continue;
        }
        let r = scrub_dataset(state, id, ScrubDepth::Footer);
        if !r.ok {
            failed += 1;
            act_on_scrub_failure(state, &r);
        }
    }
    // Datasets on disk that the cache does not hold. Everything above sweeps
    // `state.cache.ids()`, what the node is serving, and that set is wrong for one fault
    // class: a stored `manifest.json` that will not parse keeps its dataset out of the cache
    // (`cache::apply_scan` skips it on every reload), so it stops being served and the sweep
    // never looks at it while `GET /datasets/{id}/state` still answers `visible`.
    //
    // A directory named like a dataset that the cache does not hold is either mid-publish
    // (harmless: it scrubs clean and the next reload picks it up) or damaged in a way that
    // kept it out, which is what wants quarantining. `Footer` depth: the manifest parse this
    // exists for happens first inside `scrub_dataset`, and anything deeper would be wasted on
    // a dataset nothing is serving.
    for id in uncached_store_dirs(state, &ids) {
        let r = scrub_dataset(state, &id, ScrubDepth::Footer);
        // The same route as the two passes above: `act_on_scrub_failure` keeps a transient
        // fault counted and warned about but never quarantined. An uncached store is the one
        // nothing else looks at, so dropping the transient here would hide an I/O fault.
        if !r.ok {
            failed += 1;
            act_on_scrub_failure(state, &r);
        }
    }

    // At-rest composition rides along with the sweep that already walks the store, so the
    // half-encrypted state that enabling PME leaves behind is visible between `doctor` runs.
    // PME-only: on a node that never enabled it every store is plaintext, which is not a
    // finding.
    if state.config.has_transit_key() {
        let tally = at_rest_tally(&state.config.service.data_dir);
        crate::metrics::record_at_rest(tally.plaintext, tally.encrypted, tally.indeterminate);
    }
    failed
}

/// Re-verify the quarantined set at the deepest depth available and lift the quarantine on a
/// pass, returning how many are still failing for the sweep's gauge.
///
/// This is the un-quarantine path, and it measures instead of assuming: `ScrubFailed` is not
/// node-retriable, so without it the only way out is `drain_retriable_errors` deleting the
/// status row at boot, which re-serves data the node has proven corrupt.
///
/// `Digest` depth is required. A dataset quarantined for silent page bit-rot passes `Footer`
/// every time, because the intact footer is what makes the rot silent. `Digest` is `Footer`
/// plus the sidecar, and those two are the only depths the sweep quarantines at, so a pass
/// here is a pass at or above whatever depth detected the failure. Not `FullDigest`: the row
/// validation makes that tier expensive and no quarantine is ever raised at `Full` depth. On
/// a PME store `Digest` degrades to footer-only, the deepest check that exists for `PARE`.
///
/// A still-failing dataset is counted, because `gdi_store_scrub_failed` gauges the datasets
/// currently failing verification rather than the rate of new failures: leaving a standing
/// failure out would clear `StoreScrubFailed` (`> 0`, `for: 0m`) with the dataset still
/// corrupt and withheld. The quarantine itself is left as it stands, with no second
/// alert-tagged line and no second audit event. Ids in `checked` were scrubbed this pass by
/// the digest tier, which counted any it quarantined, so nothing counts twice.
///
/// Cost is bounded by the quarantined set, which is normally empty and always small.
fn reverify_quarantined<'a>(
    state: &AppState,
    ids: &'a [String],
    checked: &mut std::collections::HashSet<&'a str>,
) -> usize {
    let mut still_failing = 0usize;
    for id in ids {
        if checked.contains(id.as_str()) || !state.is_scrub_quarantined(id) {
            continue;
        }
        let r = scrub_dataset(state, id, ScrubDepth::Digest);
        checked.insert(id.as_str());
        if r.ok {
            crate::ingest_runtime::clear_scrub_quarantine(state, id);
        } else {
            // Counted whether the re-verification failed permanently or transiently: the
            // dataset is still quarantined and withheld either way. Dropping the transient
            // arm would set `gdi_store_scrub_failed` to 0 on a volume hiccup, clearing
            // `StoreScrubFailed` with the corruption standing. The two sibling loops count
            // with `!r.ok` for the same reason.
            still_failing += 1;
            tracing::debug!(
                dataset = %id,
                detail = %r.detail,
                transient = r.transient,
                "store scrub: quarantined dataset still fails re-verification"
            );
        }
    }
    still_failing
}

/// Dataset directories present under `data_dir` that the cache does not hold.
///
/// The sweep's other passes enumerate the cache, what the node serves. This is the
/// complement: what is on disk and *should* be served but is not. Usually that is a dataset
/// published moments ago, before the next cache reload, which scrubs clean; the membership
/// that matters is a store damaged in a way that keeps it out of the cache, which nothing
/// else would look at.
///
/// Dot-prefixed entries are skipped: `.incoming/` is ingest scratch by construction, and the
/// status/lock files are not directories. Only names that are valid dataset ids qualify, so
/// an operator's stray directory is not scrubbed or quarantined.
///
/// A directory under a live deletion-intent marker
/// ([`gdi_node_standalone_core::util::is_deleting`]) is skipped too. `erase_dataset` purges
/// the status row under the lock and removes the directory off it, so in that window the id
/// is uncached, valid and present, and a half-removed store scrubs `Indeterminate`.
/// Quarantining it would synthesise an `error` row for a dataset the operator just erased,
/// unclearable afterwards because the id is not cached.
fn uncached_store_dirs(state: &AppState, cached: &[String]) -> Vec<String> {
    let held: std::collections::HashSet<&str> = cached.iter().map(String::as_str).collect();
    let data_dir = &state.config.service.data_dir;
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .filter(|name| !name.starts_with('.'))
        .filter(|name| gdi_node_standalone_core::id::is_valid_dataset_id(name))
        .filter(|name| !held.contains(name.as_str()))
        .filter(|name| !gdi_node_standalone_core::util::is_deleting(data_dir, name))
        .collect();
    // Deterministic order so a repeated sweep reports the same first failure.
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn at_rest_form_separates_par1_pare_and_neither() {
        let tmp = tempfile::tempdir().unwrap();
        let mk = |name: &str, body: Option<&[u8]>| {
            let dir = tmp.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            if let Some(body) = body {
                std::fs::write(
                    dir.join("allele-freq.chr3.4.br10000000.aaaaaaaaaaaaaaaa.parquet"),
                    body,
                )
                .unwrap();
            }
            dir
        };

        assert_eq!(
            at_rest_form(&mk("plain", Some(b"PAR1...."))),
            AtRestForm::Plaintext
        );
        assert_eq!(
            at_rest_form(&mk("pme", Some(b"PARE...."))),
            AtRestForm::Encrypted
        );
        // The three worlds a `!is_plaintext_store` shorthand collapses into "encrypted": no
        // parquet at all, one truncated below the 4-byte magic, and an absent directory.
        // Each is Indeterminate, a form the type forces a caller to name.
        assert_eq!(at_rest_form(&mk("empty", None)), AtRestForm::Indeterminate);
        assert_eq!(
            at_rest_form(&mk("truncated", Some(b"PA"))),
            AtRestForm::Indeterminate
        );
        assert_eq!(
            at_rest_form(&tmp.path().join("absent")),
            AtRestForm::Indeterminate
        );
    }

    /// A directory the node cannot read is `Unreadable`, not `Indeterminate`.
    ///
    /// The two drive opposite handling: `Indeterminate` quarantines, `Unreadable` leaves the
    /// dataset served. Collapsing them lets one `EIO`/`EACCES` on a live data volume withhold
    /// a healthy dataset until an operator intervenes.
    ///
    /// Asserted in both directions, so this cannot pass by reporting every directory
    /// unreadable.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_directory_is_distinct_from_a_missing_parquet() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("locked");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("allele-freq.chr3.4.br10000000.aaaaaaaaaaaaaaaa.parquet"),
            b"PAR1....",
        )
        .unwrap();

        // Readable: an ordinary plaintext store.
        assert_eq!(at_rest_form(&dir), AtRestForm::Plaintext);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        if test_util::skip_if_root() {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            return;
        }
        let form = at_rest_form(&dir);
        // Restore before asserting so a failure cannot leave an undeletable tempdir behind.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            form,
            AtRestForm::Unreadable,
            "a directory that cannot be opened says nothing about the data it holds"
        );
    }

    /// `first_encrypted_store` must never hand `pme reseal` a store with nothing in it.
    ///
    /// A directory with no parquet is [`AtRestForm::Indeterminate`], not `Encrypted`. Were it
    /// treated as encrypted, the reseal would "prove" the current Transit key against zero
    /// files, succeed vacuously, and clear the sentinel latch without exercising the key,
    /// turning the verb into the undocumented `rm` it exists to replace.
    #[cfg(feature = "pme")]
    #[test]
    fn store_form_predicates_do_not_overlap_and_skip_empty_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let mk = |id: &str, magic: Option<&[u8]>| {
            let dir = data_dir.join(id);
            std::fs::create_dir_all(&dir).unwrap();
            if let Some(magic) = magic {
                std::fs::write(
                    dir.join("allele-freq.chr3.4.br10000000.aaaaaaaaaaaaaaaa.parquet"),
                    magic,
                )
                .unwrap();
            }
            dir
        };
        let plain = mk("GDI-EE-UTARTU-20260409143052837", Some(b"PAR1...."));
        let enc = mk("GDI-EE-UTARTU-20260409143052838", Some(b"PARE...."));
        // A dataset directory with no parquet: neither form.
        let empty = mk("GDI-EE-UTARTU-20260409143052839", None);

        assert_eq!(at_rest_form(&plain), AtRestForm::Plaintext);
        assert_eq!(at_rest_form(&enc), AtRestForm::Encrypted);
        assert_eq!(
            at_rest_form(&empty),
            AtRestForm::Indeterminate,
            "an empty store is neither form, the case a `!is_plaintext_store` shorthand \
             gets wrong"
        );

        // The reseal probe picks the real encrypted store, never the empty one.
        assert_eq!(first_encrypted_store(data_dir), Some(enc));
        // A store with nothing encrypted yields None, so the reseal reports "nothing to
        // verify against" instead of claiming a proof it did not perform.
        let only_plain = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(only_plain.path().join("GDI-EE-UTARTU-20260409143052837")).unwrap();
        assert_eq!(first_encrypted_store(only_plain.path()), None);
    }

    /// The single at-rest tally that both `doctor` and the `gdi_datasets_at_rest` gauge read,
    /// so the two can never disagree about what the store holds.
    ///
    /// The indeterminate store is the case that matters. A `(plaintext, total)` tally letting
    /// both consumers derive `encrypted = total - plaintext` would count a dataset whose
    /// parquet has been deleted as encrypted, so each form is counted directly.
    #[test]
    fn at_rest_tally_counts_each_form_separately() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        for (id, magic) in [
            ("GDI-EE-UTARTU-20260409143052837", Some(&b"PAR1...."[..])),
            ("GDI-EE-UTARTU-20260409143052838", Some(&b"PARE...."[..])),
            ("GDI-EE-UTARTU-20260409143052839", None), // parquet deleted
            ("GDI-EE-UTARTU-20260409143052840", Some(&b"PA"[..])), // truncated
        ] {
            let dir = data_dir.join(id);
            std::fs::create_dir_all(&dir).unwrap();
            if let Some(magic) = magic {
                std::fs::write(
                    dir.join("allele-freq.chr3.4.br10000000.aaaaaaaaaaaaaaaa.parquet"),
                    magic,
                )
                .unwrap();
            }
        }
        // Non-dataset entries (the override directory, the status index, a stray file) are
        // not dataset stores and must not inflate the denominator.
        std::fs::create_dir_all(data_dir.join("overrides")).unwrap();
        std::fs::write(data_dir.join(".status.json"), b"{}").unwrap();

        let tally = at_rest_tally(data_dir);
        assert_eq!(tally.plaintext, 1);
        assert_eq!(
            tally.encrypted, 1,
            "only the PARE store is encrypted; the deleted and truncated ones must not be \
             counted here: folding them in reports a deleted or truncated parquet as \
             at-rest encrypted"
        );
        assert_eq!(tally.indeterminate, 2);
        assert_eq!(tally.total(), 4);
    }

    #[test]
    fn at_rest_tally_on_an_absent_data_dir_is_empty_not_a_panic() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            at_rest_tally(&tmp.path().join("absent")),
            AtRestTally::default()
        );
    }

    /// The scrub must fail a published dataset whose parquet files are gone.
    ///
    /// A depth gate of `!is_plaintext_store` is also true of a store with no readable parquet,
    /// so such a dataset takes the `PME: footer-only` exit and passes at every depth:
    /// `verify --digest` reports `0 failed` and exit 0, and the rotating digest tier never
    /// quarantines it, even though `core::digest` can answer `Mismatch("… (missing)")` for
    /// the very files the sidecar names.
    #[test]
    fn scrub_fails_a_dataset_whose_parquet_was_deleted() {
        use gdi_node_standalone_core::cache::StatusIndex;
        use gdi_node_standalone_core::config::ServiceConfig;

        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let id = "GDI-EE-UTARTU-20260409143052837";
        let dir = data_dir.join(id);
        std::fs::create_dir_all(&dir).unwrap();
        // Everything a published plaintext dataset carries except the parquet itself: the
        // digest sidecar still attests to a file that is no longer on disk.
        std::fs::write(
            dir.join("manifest.json"),
            test_util::stored_manifest_json(id),
        )
        .unwrap();
        std::fs::write(
            dir.join("parquet-digests.json"),
            br#"{"allele-freq.chr1.0.br10000000.aaaaaaaaaaaaaaaa.parquet":"sha256:00"}"#,
        )
        .unwrap();

        let toml = format!(
            "[service]\nbase_url=\"https://n.example.org/\"\ndata_dir=\"{}\"\n\
             [catalogs]\ngdi-aggregated=\"GoE\"\n\
             [beacon]\nid=\"o.n\"\nname=\"N\"\nenvironment=\"test\"\n",
            data_dir.display()
        );
        let config = ServiceConfig::from_toml_str(&toml).unwrap();
        let state = crate::state::AppState::new(
            config,
            StatusIndex::new(),
            crate::identities::NodeIdentities::empty(),
        );

        // Footer matters most of the four: it is what `run_scrub_sweep`'s per-pass tier, the
        // boot self-test and a bare `verify` all run, so it decides whether corruption is
        // noticed on the first sweep after it appears rather than only when the dataset's
        // turn comes in the rotating digest tier.
        for depth in [
            ScrubDepth::Footer,
            ScrubDepth::Full,
            ScrubDepth::Digest,
            ScrubDepth::FullDigest,
        ] {
            let result = scrub_dataset(&state, id, depth);
            assert!(
                !result.ok,
                "{depth:?} must fail a dataset with no readable parquet; got ok with {:?}",
                result.detail
            );
            assert!(
                result.detail.contains("no readable parquet"),
                "the failure must name the cause, not report a PME fallback; got {:?}",
                result.detail
            );
        }
    }

    /// A stored `manifest.json` that will not parse is a data fault, not a silent skip.
    ///
    /// `cache::apply_scan` drops such a dataset from the cache on every reload, so Beacon, the
    /// `datasets` listing and the FDP all stop serving it, while the status index (and
    /// therefore `GET /datasets/{id}/state`, `GET /datasets` and `gdi-dataset-tool status`)
    /// goes on reporting `visible`. operating.md §1 promises "the next sweep quarantines
    /// the dataset and releases both"; this is that promise for the manifest class.
    #[test]
    fn scrub_fails_a_dataset_whose_manifest_does_not_parse() {
        let (state, _tmp, id, dir) = store_with_one_dataset();
        // Valid parquet and digests left untouched: the manifest is the only fault.
        std::fs::write(dir.join("manifest.json"), b"{ this is not json").unwrap();

        let r = scrub_dataset(&state, &id, ScrubDepth::Footer);
        assert!(!r.ok, "an unparseable stored manifest must fail the scrub");
        assert!(
            !r.transient,
            "it is attributable to the data, so it must quarantine rather than merely count"
        );
        assert!(
            r.detail.contains("manifest.json does not parse"),
            "the detail must name the cause an operator has to fix; got {:?}",
            r.detail
        );
    }

    /// The counterpart: an I/O fault reading the manifest says nothing about the data.
    ///
    /// The same rule the footer probe and `AtRestForm::Unreadable` follow. Withholding a
    /// dataset because one read returned EACCES turns a blip into an operator-action outage.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_manifest_is_transient_not_a_quarantine() {
        use std::os::unix::fs::PermissionsExt as _;
        let (state, _tmp, id, dir) = store_with_one_dataset();
        let m = dir.join("manifest.json");
        std::fs::write(&m, test_util::stored_manifest_json(&id)).unwrap();
        std::fs::set_permissions(&m, std::fs::Permissions::from_mode(0o000)).unwrap();
        if test_util::skip_if_root() {
            std::fs::set_permissions(&m, std::fs::Permissions::from_mode(0o644)).unwrap();
            return;
        }

        let r = scrub_dataset(&state, &id, ScrubDepth::Footer);
        assert!(
            r.transient,
            "an unreadable manifest is an I/O fault, not a finding about the data; got {:?}",
            r.detail
        );
        std::fs::set_permissions(&m, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// A quarantined dataset whose re-verification fails transiently is still quarantined and
    /// withheld, so it still counts. Dropping the transient arm would set
    /// `gdi_store_scrub_failed` to 0 on a volume hiccup, clearing `StoreScrubFailed` with the
    /// corruption standing, and re-fire it on recovery.
    #[cfg(unix)]
    #[test]
    fn a_transient_reverification_failure_keeps_the_quarantined_dataset_counted() {
        use std::os::unix::fs::PermissionsExt as _;
        let (state, _tmp, id, dir) = store_with_one_dataset();
        crate::ingest_runtime::quarantine_scrub_failure(&state, &id, "digest mismatch");
        assert!(
            state.is_scrub_quarantined(&id),
            "precondition: the dataset is quarantined"
        );
        let m = dir.join("manifest.json");
        std::fs::set_permissions(&m, std::fs::Permissions::from_mode(0o000)).unwrap();
        if test_util::skip_if_root() {
            std::fs::set_permissions(&m, std::fs::Permissions::from_mode(0o644)).unwrap();
            return;
        }

        let ids = vec![id.clone()];
        let mut checked = std::collections::HashSet::new();
        let still_failing = reverify_quarantined(&state, &ids, &mut checked);
        std::fs::set_permissions(&m, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(
            still_failing, 1,
            "a transiently unreadable quarantined dataset is still failing, and must count"
        );
        assert!(
            state.is_scrub_quarantined(&id),
            "a transient failure neither clears nor re-quarantines"
        );
    }

    /// The sweep must ask the disk, not only the cache.
    ///
    /// A dataset kept out of the cache by a damaged store is the one nothing else looks at,
    /// so enumerating only `cache.ids()` makes the manifest-corruption class invisible.
    /// Ingest scratch and an operator's stray directory must not be swept, or the sweep
    /// quarantines things that are not datasets, and neither may a directory whose erasure is
    /// in flight, or the sweep resurrects what was just erased.
    #[test]
    fn uncached_store_dirs_finds_damaged_stores_and_ignores_everything_else() {
        let (state, _tmp, cached_id, _dir) = store_with_one_dataset();
        let data_dir = &state.config.service.data_dir;
        let orphan = "GDI-EE-UTARTU-20260409143052999";
        // Uncached, valid and present, but under a deletion-intent marker: the window
        // between `erase_dataset`'s status purge and its directory removal.
        let erasing = "GDI-EE-UTARTU-20260409143052998";
        for name in [orphan, erasing, ".incoming", "not-a-dataset-id"] {
            std::fs::create_dir_all(data_dir.join(name)).unwrap();
        }
        gdi_node_standalone_core::util::mark_deleting(data_dir, erasing).unwrap();
        // A file named like a dataset is not a store.
        std::fs::write(data_dir.join("GDI-EE-UTARTU-20260409143052111"), b"x").unwrap();

        let found = uncached_store_dirs(&state, std::slice::from_ref(&cached_id));

        assert_eq!(
            found,
            vec![orphan.to_owned()],
            "only dataset-id-named directories absent from the cache qualify: ingest scratch \
             (`.incoming`), non-id names, plain files and a directory whose erasure is in \
             flight must be left alone"
        );
        assert!(
            !found.contains(&cached_id),
            "a dataset the cache already holds is swept by the other passes, not this one"
        );
    }

    /// A transient failure on a store the cache does not hold must be counted like every
    /// other transient, not silently dropped. The other two loops route it through
    /// `act_on_scrub_failure`, which warns and leaves it alone. An uncached store nothing
    /// else looks at is where a swallowed I/O fault stays invisible.
    #[cfg(unix)]
    #[test]
    fn a_transient_failure_on_an_uncached_store_is_counted_not_dropped_nor_quarantined() {
        use std::os::unix::fs::PermissionsExt as _;
        let (state, _tmp, _fixture_id, fixture_dir) = store_with_one_dataset();
        // The fixture's own store is a 4-byte stand-in the footer probe rejects, and only
        // the unreadable store below should be on disk for this sweep.
        std::fs::remove_dir_all(&fixture_dir).unwrap();
        let data_dir = state.config.service.data_dir.clone();
        let unreadable = "GDI-EE-UTARTU-20260409143052997";
        let dir = data_dir.join(unreadable);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("manifest.json"),
            test_util::stored_manifest_json(unreadable),
        )
        .unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        if test_util::skip_if_root() {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }

        let failed = run_scrub_sweep(&state, ScrubPass::Periodic);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(
            failed, 1,
            "the unreadable store is a (transient) failure and must be counted"
        );
        assert!(
            !state.is_scrub_quarantined(unreadable),
            "an I/O fault says nothing about the data: never quarantined"
        );
        assert!(
            state.status.lock().unwrap().get(unreadable).is_none(),
            "no status row is synthesised for a transient fault"
        );
    }

    /// A store on disk holding one plaintext dataset with a valid manifest and a real
    /// parquet, plus the `AppState` that addresses it. Returns `(state, tmp, id, dir)`; `tmp`
    /// must be held, or the directory is removed out from under the test.
    fn store_with_one_dataset() -> (
        crate::state::AppState,
        tempfile::TempDir,
        String,
        std::path::PathBuf,
    ) {
        use gdi_node_standalone_core::cache::StatusIndex;
        use gdi_node_standalone_core::config::ServiceConfig;

        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let id = "GDI-EE-UTARTU-20260409143052837".to_owned();
        let dir = data_dir.join(&id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("manifest.json"),
            test_util::stored_manifest_json(&id),
        )
        .unwrap();
        // A minimal plaintext parquet: the footer probe's at-rest classification reads only
        // the 4-byte magic, and the probe tolerates a file it cannot fully decode by
        // reporting it, which is not what these tests are about.
        std::fs::write(
            dir.join("allele-freq.chr1.0.br10000000.aaaaaaaaaaaaaaaa.parquet"),
            b"PAR1",
        )
        .unwrap();

        let toml = format!(
            "[service]\nbase_url=\"https://n.example.org/\"\ndata_dir=\"{}\"\n\
             [catalogs]\ngdi-aggregated=\"GoE\"\n\
             [beacon]\nid=\"o.n\"\nname=\"N\"\nenvironment=\"test\"\n",
            data_dir.display()
        );
        let config = ServiceConfig::from_toml_str(&toml).unwrap();
        let state = crate::state::AppState::new(
            config,
            StatusIndex::new(),
            crate::identities::NodeIdentities::empty(),
        );
        (state, tmp, id, dir)
    }
}
