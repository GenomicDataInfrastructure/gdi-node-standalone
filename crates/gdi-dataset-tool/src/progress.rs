//! Terminal progress bars for the tool's long-running streams.
//!
//! Built on [`indicatif`]. Two rules keep the machine-readable contract intact:
//!
//! * bars draw to stderr only, so the stdout result and `--format json` line are never
//!   touched;
//! * they are shown only when [`enabled`] holds: stderr is a TTY and `-q` is not in
//!   effect. Off a terminal (CI, pipes, capture) every bar is hidden, but a throttled
//!   heartbeat still prints periodic progress lines to stderr unless `-q` silences it, so
//!   a multi-minute `build` is not mistaken for a hang.
//!
//! Callers keep a single code path: a progress handle always exists, and when progress is
//! disabled its bars are [`ProgressBar::hidden`] no-ops. Three shapes cover the tool:
//! [`ConvertProgress`] (one byte bar per source VCF, for `build`), [`StreamProgress`] (a
//! single byte bar for a one-stream operation: `pack`, `unpack`, `upload`, `download`),
//! and [`CountProgress`] (a discrete item bar for `check`/`status`). [`active`] is the
//! gate every command's call site uses.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::output::Verbosity;

/// How often the non-TTY heartbeat prints a progress line.
///
/// Long enough that a CI log stays readable over a multi-minute convert, short enough that
/// a wedged run is obvious well before anyone reaches for Ctrl-C.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// How often the heartbeat thread wakes to check whether it should stop. Decoupled from
/// [`HEARTBEAT_INTERVAL`] so a finished command exits promptly instead of blocking up to a
/// full interval on a sleeping thread.
const HEARTBEAT_POLL: Duration = Duration::from_millis(250);

/// Whether live progress bars should be drawn: interactive (`is_terminal`) and not
/// silenced by `-q` (verbosity at least [`Verbosity::Normal`]). Pure so it is unit-tested
/// without a real terminal; production call sites use [`active`], which supplies the real
/// verbosity and `std::io::stderr().is_terminal()`.
#[must_use]
pub fn enabled(verbosity: Verbosity, is_terminal: bool) -> bool {
    is_terminal && verbosity >= Verbosity::Normal
}

/// Whether the line-oriented progress heartbeat should run: the case where live bars are
/// not drawn but the operator has not asked for silence.
///
/// `indicatif` renders nothing off a terminal, so behind a pipe a multi-minute `build`
/// would print nothing between the first line and the result, which is indistinguishable
/// from a hang. This is the complement of [`enabled`]: bars with a terminal, throttled
/// lines without one, nothing under `-q`.
#[must_use]
pub fn heartbeat_enabled(verbosity: Verbosity, is_terminal: bool) -> bool {
    !is_terminal && verbosity >= Verbosity::Normal
}

/// The real-process gate for [`heartbeat_enabled`] (mirrors [`active`]).
#[must_use]
fn heartbeat_active() -> bool {
    use std::io::IsTerminal as _;
    heartbeat_enabled(crate::output::verbosity(), std::io::stderr().is_terminal())
}

/// Render one progress line per unfinished bar. Shared by the heartbeat thread so the
/// format lives in exactly one place.
fn heartbeat_lines(bars: &[ProgressBar], labels: &[String]) -> Vec<String> {
    bars.iter()
        .enumerate()
        .filter_map(|(i, bar)| {
            let total = bar.length()?;
            let pos = bar.position();
            // An indeterminate (0-length) or already-complete bar has nothing useful to say.
            if total == 0 || pos >= total {
                return None;
            }
            let pct = pos.saturating_mul(100) / total;
            let label = labels.get(i).map_or("", String::as_str);
            Some(format!("progress: {label} {pct}% ({pos}/{total} bytes)"))
        })
        .collect()
}

/// A background thread that prints throttled progress lines to stderr when live bars are
/// unavailable (non-TTY).
///
/// Sampling the bars from a separate thread, rather than hooking the write path, works
/// identically for [`ConvertProgress::inc`] and for the wrapped reader/writer streams of
/// [`StreamProgress`], and costs the hot path nothing.
struct Heartbeat {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Heartbeat {
    /// Spawn the ticker over `bars` (cheap `Arc` clones of the real bars).
    fn spawn(bars: Vec<ProgressBar>, labels: Vec<String>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut last = Instant::now();
            while !flag.load(Ordering::Relaxed) {
                std::thread::sleep(HEARTBEAT_POLL);
                if last.elapsed() < HEARTBEAT_INTERVAL {
                    continue;
                }
                last = Instant::now();
                for line in heartbeat_lines(&bars, &labels) {
                    eprintln!("{line}");
                }
            }
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            // A panicked ticker must not poison the command's exit path: it only prints.
            let _ = handle.join();
        }
    }
}

/// The longest bar label (a file name) drawn as a `{prefix}`; longer names are elided in
/// the middle by [`elide_label`]. An upper bound only: [`label_budget`] narrows it to what
/// the terminal can spare.
const MAX_LABEL_CHARS: usize = 34;

/// The shortest label worth drawing. Below this the elision leaves too little of the file
/// name to tell two sources apart, and a bar with no legible label is worse than a
/// narrower bar.
const MIN_LABEL_CHARS: usize = 12;

/// Columns [`byte_style`] needs for everything other than the label: `" ["`, `"] "`, the
/// widest realistic counters, rate and ETA (`"424.00 KiB/1.83 GiB (0%) 92.24 MiB/s ETA
/// 20s"` is 44 columns), plus a few cells of bar.
const BAR_FIXED_COLUMNS: usize = 60;

/// How many columns the label may take on a terminal `width` columns wide.
///
/// `{wide_bar}` absorbs whatever is left after the prefix and the counters, so a label
/// bounded only by a constant can leave the bar nothing: at 80 columns a 34-char label plus
/// 4 cells of brackets plus a 42-char numeric tail comes to exactly 80, and indicatif then
/// draws the bar as an empty `[]`. The label is the part that gives ground.
#[must_use]
fn label_budget(width: usize) -> usize {
    width
        .saturating_sub(BAR_FIXED_COLUMNS)
        .clamp(MIN_LABEL_CHARS, MAX_LABEL_CHARS)
}

/// The terminal's width in columns, or [`MAX_LABEL_CHARS`]'s comfortable default when
/// there is no terminal to ask (piped output draws no bars anyway).
fn terminal_width() -> usize {
    let cols = usize::from(console::Term::stderr().size().1);
    if cols == 0 { 100 } else { cols }
}

/// Elide `name` in the middle to at most [`MAX_LABEL_CHARS`] chars, keeping the start and
/// the extension-bearing tail (`COVID.monogneic.aggr…AFs.GRCh38.vcf.gz`).
///
/// indicatif draws multi-bar frames as width-padded lines with no hard newlines, so a line
/// wider than the terminal wraps, breaks the redraw's row accounting, and turns the whole
/// region into run-together, space-padded junk. Bounding the label, with `{wide_bar}`
/// absorbing the remainder, keeps every line inside the terminal. Tail-truncation would be
/// worse than none: a `.vcf` / `.vcf.gz` twin pair differs only at the end.
fn elide_label(name: &str) -> String {
    elide_label_to(name, label_budget(terminal_width()))
}

/// [`elide_label`] against an explicit budget, so the arithmetic is testable without a
/// terminal.
fn elide_label_to(name: &str, budget: usize) -> String {
    let chars: Vec<char> = name.chars().collect();
    if chars.len() <= budget {
        return name.to_owned();
    }
    let head = budget / 2;
    let tail = budget.saturating_sub(head + 1);
    let mut out: String = chars[..head].iter().collect();
    out.push('…');
    out.extend(&chars[chars.len() - tail..]);
    out
}

/// The byte-oriented bar style: a bar, transferred/total, percent, rate, and ETA.
/// `{wide_bar}` rather than a fixed width, so indicatif fits each line to the terminal.
/// See [`elide_label`] for why an over-wide line corrupts the whole frame.
fn byte_style() -> ProgressStyle {
    // `unwrap` is on a compile-time-constant template; a bad template is a programming
    // error caught by the unit/integration tests, not a runtime condition.
    ProgressStyle::with_template(
        "{prefix:.bold} [{wide_bar}] {bytes}/{total_bytes} ({percent}%) {binary_bytes_per_sec} ETA {eta}",
    )
    .unwrap_or_else(|_| ProgressStyle::default_bar())
    .progress_chars("=> ")
}

/// A group of per-source byte progress bars for a `convert_vcf_group` run.
///
/// One bar per source VCF, each sized to that file's on-disk byte length, advanced by
/// [`Self::inc`] as the converter reports compressed bytes read. When progress is
/// disabled the bars are hidden no-ops, so the conversion call site is unconditional.
pub struct ConvertProgress {
    /// `Some` only when enabled. Owns the shared draw target the bars render into, and
    /// the channel for [`Self::note`] lines printed cleanly above the live bars.
    multi: Option<MultiProgress>,
    /// One bar per source, index-aligned with the converter's source list.
    bars: Vec<ProgressBar>,
    /// The non-TTY ticker. `Some` only when bars are hidden but output is not silenced;
    /// see [`heartbeat_enabled`]. Dropping it stops the thread.
    _heartbeat: Option<Heartbeat>,
}

impl ConvertProgress {
    /// Build a progress group for sources whose on-disk sizes are `sizes` and whose short
    /// labels (e.g. file names) are `labels` (index-aligned). When `enabled` is false
    /// every bar is hidden and [`Self::inc`]/[`Self::finish`] are cheap no-ops. A
    /// non-silenced, non-terminal run still gets a throttled heartbeat, because a
    /// multi-minute convert that prints nothing is indistinguishable from a hang.
    #[must_use]
    pub fn new(sizes: &[u64], labels: &[String], enabled: bool) -> Self {
        if !enabled {
            // Bars are hidden no-ops, but still carry their length so byte accounting
            // (and tests) stay faithful off a terminal.
            let bars: Vec<ProgressBar> = sizes
                .iter()
                .map(|&size| {
                    let bar = ProgressBar::hidden();
                    bar.set_length(size);
                    bar
                })
                .collect();
            let heartbeat =
                heartbeat_active().then(|| Heartbeat::spawn(bars.clone(), labels.to_vec()));
            return Self {
                multi: None,
                bars,
                _heartbeat: heartbeat,
            };
        }
        let multi = MultiProgress::new();
        let style = byte_style();
        let bars = sizes
            .iter()
            .enumerate()
            .map(|(i, &size)| {
                let pb = multi.add(ProgressBar::new(size));
                pb.set_style(style.clone());
                if let Some(label) = labels.get(i) {
                    pb.set_prefix(label.clone());
                }
                pb
            })
            .collect();
        Self {
            multi: Some(multi),
            bars,
            // Live bars are drawing; a heartbeat would just fight them for the terminal.
            _heartbeat: None,
        }
    }

    /// Build a progress group for `paths`, sizing each bar to that file's on-disk byte
    /// length (`0` if its metadata cannot be read, which shows an indeterminate total) and
    /// labelling it with the file name. See [`Self::new`] for `enabled`.
    #[must_use]
    pub fn for_paths(paths: &[std::path::PathBuf], enabled: bool) -> Self {
        let sizes: Vec<u64> = paths
            .iter()
            .map(|p| std::fs::metadata(p).map_or(0, |m| m.len()))
            .collect();
        let labels: Vec<String> = paths
            .iter()
            .map(|p| {
                p.file_name()
                    .map(|n| elide_label(&n.to_string_lossy()))
                    .unwrap_or_default()
            })
            .collect();
        Self::new(&sizes, &labels, enabled)
    }

    /// The configured total (file length in bytes) of source `idx`'s bar, if any.
    #[must_use]
    pub fn total(&self, idx: usize) -> Option<u64> {
        self.bars.get(idx).and_then(ProgressBar::length)
    }

    /// Advance source `idx`'s bar by `n` freshly-read bytes. Out-of-range `idx` is ignored
    /// (the converter only ever reports in-range indices).
    pub fn inc(&self, idx: usize, n: u64) {
        if let Some(bar) = self.bars.get(idx) {
            bar.inc(n);
        }
    }

    /// The current byte position of source `idx`'s bar (0 if out of range). Tracked even
    /// for hidden bars, so it is a faithful witness of [`Self::inc`] in tests.
    #[must_use]
    pub fn position(&self, idx: usize) -> u64 {
        self.bars.get(idx).map_or(0, ProgressBar::position)
    }

    /// Print a milestone line cleanly: above the live bars when enabled, else through the
    /// normal verbosity-gated stderr progress path (preserving non-interactive output).
    pub fn note(&self, msg: &str) {
        match &self.multi {
            Some(multi) => {
                let _ = multi.println(msg);
            }
            None => crate::output::progress(msg),
        }
    }

    /// Finish and clear every bar (call once the conversion returns).
    pub fn finish(&self) {
        for bar in &self.bars {
            bar.finish_and_clear();
        }
    }
}

/// Whether progress bars should be shown for the current process: a convenience over
/// [`enabled`] that reads the global verbosity and the real `stderr` terminal. Every
/// command's call site uses this; [`enabled`] stays pure for unit tests.
#[must_use]
pub fn active() -> bool {
    use std::io::IsTerminal as _;
    enabled(crate::output::verbosity(), std::io::stderr().is_terminal())
}

/// The discrete item-count bar style: a bar, `pos/len`, and a trailing message.
fn count_style() -> ProgressStyle {
    ProgressStyle::with_template("{prefix:.bold} [{bar:30}] {pos}/{len} {wide_msg}")
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("=> ")
}

/// Build a single bar of expected length `total`, prefixed with `label` and drawn in
/// `style`. When `enabled` is false the bar is a hidden no-op, but still carries its length
/// and prefix, so `total()` and the heartbeat stay faithful off a terminal.
fn labelled_bar(total: u64, label: &str, style: ProgressStyle, enabled: bool) -> ProgressBar {
    let bar = if enabled {
        ProgressBar::new(total)
    } else {
        ProgressBar::hidden()
    };
    bar.set_style(style);
    bar.set_length(total);
    bar.set_prefix(elide_label(label));
    bar
}

/// A single byte-oriented progress bar for a one-stream operation (pack, unpack, upload,
/// download). Hidden no-op when disabled; advance it by wrapping the stream
/// ([`Self::wrap_write`] / [`Self::wrap_read`]) or with [`Self::set_position`]. Milestone
/// lines route through [`Self::note`] so they print cleanly above a live bar, or via the
/// plain stderr path off a terminal.
///
/// `Clone` is cheap (the bar is reference-counted) and yields a handle to the same bar,
/// used to drive progress from a worker thread such as the TAR builder while the original
/// stays on the calling thread for [`Self::finish`].
#[derive(Clone)]
pub struct StreamProgress {
    bar: ProgressBar,
    enabled: bool,
    /// The non-TTY ticker, shared by every clone: `StreamProgress` is cloned to drive the
    /// bar from a worker thread, and the ticker must tick once, not once per handle. The
    /// last clone to drop stops the thread.
    _heartbeat: Option<Arc<Heartbeat>>,
}

impl StreamProgress {
    /// Build a byte bar of expected length `total` (0 ⇒ indeterminate) labelled `label`.
    /// Hidden no-op when `enabled` is false; see [`active`]. A non-silenced, non-terminal
    /// run instead gets a throttled heartbeat, so packing or uploading a multi-GB package
    /// off a terminal does not look like a hang.
    #[must_use]
    pub fn new(total: u64, label: &str, enabled: bool) -> Self {
        let bar = labelled_bar(total, label, byte_style(), enabled);
        let heartbeat = (!enabled && heartbeat_active())
            .then(|| Arc::new(Heartbeat::spawn(vec![bar.clone()], vec![label.to_owned()])));
        Self {
            bar,
            enabled,
            _heartbeat: heartbeat,
        }
    }

    /// Wrap a writer so each write advances the bar (e.g. the TAR→encrypt pipe writer).
    #[must_use]
    pub fn wrap_write<W: std::io::Write>(&self, writer: W) -> indicatif::ProgressBarIter<W> {
        self.bar.wrap_write(writer)
    }

    /// Wrap a reader so each read advances the bar (e.g. the decrypt→extract pipe reader).
    #[must_use]
    pub fn wrap_read<R: std::io::Read>(&self, reader: R) -> indicatif::ProgressBarIter<R> {
        self.bar.wrap_read(reader)
    }

    /// Set the bar's absolute byte position (for callers that track a cumulative count).
    pub fn set_position(&self, pos: u64) {
        self.bar.set_position(pos);
    }

    /// The bar's current byte position (a faithful witness of progress in tests).
    #[must_use]
    pub fn position(&self) -> u64 {
        self.bar.position()
    }

    /// The configured total (expected byte length), if any.
    #[must_use]
    pub fn total(&self) -> Option<u64> {
        self.bar.length()
    }

    /// A Normal-level milestone line: above the live bar when enabled, else the plain
    /// verbosity-gated stderr progress path (preserving non-interactive output).
    pub fn note(&self, msg: &str) {
        if self.enabled {
            self.bar.println(msg);
        } else {
            crate::output::progress(msg);
        }
    }

    /// A Verbose-level diagnostic, routed like [`Self::note`] but shown only under `-v`.
    pub fn detail(&self, msg: &str) {
        if self.enabled {
            if crate::output::is_verbose() {
                self.bar.println(msg);
            }
        } else {
            crate::output::note(msg);
        }
    }

    /// Finish and clear the bar (call once the stream completes).
    pub fn finish(&self) {
        self.bar.finish_and_clear();
    }
}

/// A discrete item-count progress bar (e.g. datasets checked or statused). Hidden no-op
/// when disabled. [`Self::step`] advances by one item: on a terminal it updates the bar's
/// trailing message, and off a terminal it prints a `verb N/total: item` line, preserving
/// non-interactive output.
pub struct CountProgress {
    bar: ProgressBar,
    enabled: bool,
    verb: String,
}

impl CountProgress {
    /// Build an item-count bar over `total` items, prefixed/labelled by `verb` (e.g.
    /// `"checking"`). Hidden no-op when `enabled` is false; see [`active`].
    #[must_use]
    pub fn new(verb: &str, total: u64, enabled: bool) -> Self {
        let bar = labelled_bar(total, verb, count_style(), enabled);
        Self {
            bar,
            enabled,
            verb: verb.to_owned(),
        }
    }

    /// Advance by one item named `item`. On a terminal this updates the bar message; off a
    /// terminal it prints `"<verb> <n>/<total>: <item>"`.
    pub fn step(&self, item: &str) {
        self.bar.inc(1);
        if self.enabled {
            self.bar.set_message(item.to_owned());
        } else {
            let n = self.bar.position();
            let total = self.bar.length().unwrap_or(0);
            crate::output::progress(&format!("{} {n}/{total}: {item}", self.verb));
        }
    }

    /// The number of items stepped so far.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.bar.position()
    }

    /// The configured total item count, if any.
    #[must_use]
    pub fn total(&self) -> Option<u64> {
        self.bar.length()
    }

    /// Finish and clear the bar.
    pub fn finish(&self) {
        self.bar.finish_and_clear();
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    /// Labels are bounded and elided in the middle: an over-wide bar line wraps and
    /// corrupts the whole multi-bar frame, and a `.vcf`/`.vcf.gz` twin pair differs only at
    /// the end, so tail-truncation would render the twins identical.
    #[test]
    fn elide_label_bounds_length_and_keeps_both_ends() {
        // Against an explicit budget, so the assertions do not depend on the width of
        // whatever terminal, or absence of one, the test runs under.
        let at = |name: &str| elide_label_to(name, MAX_LABEL_CHARS);
        // Short names pass through untouched.
        assert_eq!(at("chr21.vcf.gz"), "chr21.vcf.gz");
        assert_eq!(
            at("recalc-pop11_sub1_chr21.vcf.gz"),
            "recalc-pop11_sub1_chr21.vcf.gz"
        );
        // A long name is elided to the cap, keeping the start and the extension tail.
        let long = "COVID.monogneic.aggregate.AFs.GRCh38.vcf.gz";
        let elided = at(long);
        assert_eq!(elided.chars().count(), MAX_LABEL_CHARS);
        assert!(elided.starts_with("COVID."), "{elided}");
        assert!(elided.ends_with(".vcf.gz"), "{elided}");
        assert!(elided.contains('…'), "{elided}");
        // The twin pair stays distinguishable after elision.
        assert_ne!(
            at("COVID.monogneic.aggregate.AFs.GRCh38.vcf"),
            at("COVID.monogneic.aggregate.AFs.GRCh38.vcf.gz")
        );
        // At a narrow budget the elision still holds both ends: whatever follows the
        // ellipsis is still a suffix of the original name.
        let narrow = elide_label_to(long, MIN_LABEL_CHARS);
        assert_eq!(narrow.chars().count(), MIN_LABEL_CHARS);
        let kept_tail = narrow
            .rsplit('…')
            .next()
            .expect("an elided label has a tail");
        assert!(!kept_tail.is_empty(), "{narrow}");
        assert!(long.ends_with(kept_tail), "{narrow}");
    }

    /// The label must leave the bar room to exist. A fixed 34-char cap plus 4 cells of
    /// brackets plus a 42-char numeric tail is exactly 80, so at 80 columns `{wide_bar}`
    /// gets zero columns and indicatif draws an empty `[]`.
    #[test]
    fn the_label_budget_always_leaves_columns_for_the_bar() {
        // The width at which a fixed label cap collapses the bar.
        assert!(
            label_budget(80) + BAR_FIXED_COLUMNS <= 80,
            "80 columns must still fit a bar"
        );
        assert_eq!(label_budget(80), 20);
        // Wide terminals stop at the readability cap rather than growing without bound.
        assert_eq!(label_budget(200), MAX_LABEL_CHARS);
        // Absurdly narrow ones keep a legible stub instead of collapsing to nothing.
        assert_eq!(label_budget(20), MIN_LABEL_CHARS);
        assert_eq!(label_budget(0), MIN_LABEL_CHARS);
    }

    /// The heartbeat covers the gap `enabled` leaves: no terminal, but no `-q` either.
    /// Overlapping `enabled` would give a TTY run both bars and lines fighting over stderr,
    /// and firing under `-q` would break the silence contract. Both edges are pinned.
    #[test]
    fn heartbeat_is_the_complement_of_live_bars_and_respects_quiet() {
        for verbosity in [Verbosity::Normal, Verbosity::Verbose] {
            // On a terminal: bars, never the heartbeat.
            assert!(enabled(verbosity, true));
            assert!(!heartbeat_enabled(verbosity, true));
            // Off a terminal: the heartbeat, never bars.
            assert!(!enabled(verbosity, false));
            assert!(heartbeat_enabled(verbosity, false));
        }
        // `-q` means silence: neither, on or off a terminal.
        assert!(!enabled(Verbosity::Quiet, false));
        assert!(!heartbeat_enabled(Verbosity::Quiet, false));
        assert!(!heartbeat_enabled(Verbosity::Quiet, true));
    }

    /// The heartbeat line must carry the label and real byte counts, and must skip bars
    /// that would say nothing useful (indeterminate or already complete).
    #[test]
    fn heartbeat_lines_report_percent_and_skip_uninformative_bars() {
        let running = ProgressBar::hidden();
        running.set_length(200);
        running.set_position(50);

        let done = ProgressBar::hidden();
        done.set_length(10);
        done.set_position(10);

        let indeterminate = ProgressBar::hidden();
        indeterminate.set_length(0);

        let labels = vec![
            "chr21.vcf".to_owned(),
            "done.vcf".to_owned(),
            "x".to_owned(),
        ];
        let lines = heartbeat_lines(&[running, done, indeterminate], &labels);

        assert_eq!(
            lines.len(),
            1,
            "only the in-flight bar is worth a line: {lines:?}"
        );
        assert_eq!(lines[0], "progress: chr21.vcf 25% (50/200 bytes)");
    }

    #[test]
    fn enabled_requires_normal_verbosity_and_a_terminal() {
        // Interactive + not quiet → show bars.
        assert!(enabled(Verbosity::Normal, true));
        assert!(enabled(Verbosity::Verbose, true));
        // `-q` silences progress even on a TTY.
        assert!(!enabled(Verbosity::Quiet, true));
        // Non-interactive (CI / pipe / capture) stays clean at every verbosity.
        assert!(!enabled(Verbosity::Normal, false));
        assert!(!enabled(Verbosity::Verbose, false));
    }

    #[test]
    fn enabled_multiprogress_path_is_panic_free() {
        // Exercises the real `MultiProgress` branch the disabled tests skip: byte-style
        // template parsing, `add`, `set_prefix`, `println`, `inc` and `finish`. Under
        // `cargo test` stderr is not a TTY, so indicatif auto-hides; this asserts the
        // enabled path is well-formed and panic-free, which is where a malformed style
        // template or format string would surface.
        let prog = ConvertProgress::new(&[10, 20], &["a.vcf".into(), "b.vcf.gz".into()], true);
        prog.note("converting VCF 1/2: a.vcf");
        prog.inc(0, 10);
        prog.inc(1, 5);
        assert_eq!(prog.position(0), 10);
        assert_eq!(prog.position(1), 5);
        prog.finish();
    }

    #[test]
    fn for_paths_sizes_each_bar_to_its_file_length() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.vcf");
        let b = dir.path().join("b.vcf.gz");
        std::fs::write(&a, b"hello").unwrap(); // 5 bytes
        std::fs::write(&b, vec![0u8; 4096]).unwrap(); // 4096 bytes
        let prog = ConvertProgress::for_paths(&[a, b], false);
        assert_eq!(prog.total(0), Some(5), "bar 0 sized to a.vcf length");
        assert_eq!(prog.total(1), Some(4096), "bar 1 sized to b.vcf.gz length");
    }

    #[test]
    fn stream_progress_sizes_bar_and_wrap_write_counts_bytes() {
        use std::io::Write as _;
        let sp = StreamProgress::new(4096, "uploading x", false);
        assert_eq!(
            sp.total(),
            Some(4096),
            "bar sized to the expected byte total"
        );
        let mut w = sp.wrap_write(std::io::sink());
        w.write_all(&[0u8; 1000]).unwrap();
        w.write_all(&[0u8; 500]).unwrap();
        drop(w);
        assert_eq!(sp.position(), 1500, "wrapped writes advance the bar");
    }

    #[test]
    fn stream_progress_set_position_tracks() {
        let sp = StreamProgress::new(100, "downloading y", false);
        sp.set_position(40);
        assert_eq!(sp.position(), 40);
        sp.set_position(50);
        assert_eq!(sp.position(), 50);
        sp.note("milestone"); // off-tty: routed to the plain path, no panic
        sp.finish();
    }

    #[test]
    fn count_progress_sizes_and_steps() {
        let cp = CountProgress::new("checking", 3, false);
        assert_eq!(cp.total(), Some(3));
        cp.step("ds-a");
        cp.step("ds-b");
        assert_eq!(cp.position(), 2);
        cp.finish();
    }

    #[test]
    fn inc_tracks_position_per_source_even_when_hidden() {
        let prog = ConvertProgress::new(&[100, 200], &[], false);
        prog.inc(0, 30);
        prog.inc(0, 20);
        prog.inc(1, 200);
        assert_eq!(prog.position(0), 50);
        assert_eq!(prog.position(1), 200);
        // Out-of-range index is ignored, not a panic.
        prog.inc(9, 5);
        prog.finish();
    }
}
