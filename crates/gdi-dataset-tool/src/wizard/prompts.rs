//! The `Prompter` seam: all interactive I/O goes through this trait so the wizard
//! flow is testable with a [`ScriptedPrompter`] and `dialoguer` stays at the edge.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::IsTerminal as _;

use crate::ToolError;

/// Interactive question source for the wizard. Implemented by [`DialoguerPrompter`]
/// (real terminal) and [`ScriptedPrompter`] (tests).
pub trait Prompter {
    /// Free-text input with an optional default; `allow_empty` permits an empty answer.
    ///
    /// # Errors
    ///
    /// Returns a [`ToolError`] on I/O failure or user abort (Ctrl-C/Esc).
    fn input(
        &self,
        prompt: &str,
        default: Option<&str>,
        allow_empty: bool,
    ) -> Result<String, ToolError>;
    /// Free-text input re-prompted until `validate` accepts it (returns `Err(msg)` to re-ask).
    ///
    /// # Errors
    ///
    /// Returns a [`ToolError`] on I/O failure, user abort, or (for [`ScriptedPrompter`]) when
    /// the scripted value fails `validate`.
    fn input_validated(
        &self,
        prompt: &str,
        default: Option<&str>,
        validate: &dyn Fn(&str) -> Result<(), String>,
    ) -> Result<String, ToolError>;
    /// A filesystem path, re-prompted until `validate` accepts it. The terminal prompter
    /// completes the path against the local filesystem on Tab; the scripted one treats this
    /// exactly like [`Self::input_validated`].
    ///
    /// # Errors
    ///
    /// As [`Self::input_validated`].
    fn input_path(
        &self,
        prompt: &str,
        default: Option<&str>,
        validate: &dyn Fn(&str) -> Result<(), String>,
    ) -> Result<String, ToolError>;
    /// A secret (an S3 credential): never echoed, never given a default. An empty answer
    /// is allowed and means "skip".
    ///
    /// # Errors
    ///
    /// Returns a [`ToolError`] on I/O failure or user abort.
    fn secret(&self, prompt: &str) -> Result<String, ToolError>;
    /// Single choice; returns the chosen index into `labels`.
    ///
    /// # Errors
    ///
    /// Returns a [`ToolError`] on I/O failure or user abort.
    fn select(&self, prompt: &str, labels: &[String], default: usize) -> Result<usize, ToolError>;
    /// Multiple choice; `checked[i]` pre-selects `labels[i]` (a shorter slice leaves the
    /// rest unchecked). Returns the chosen indices.
    ///
    /// # Errors
    ///
    /// Returns a [`ToolError`] on I/O failure or user abort.
    fn multiselect(
        &self,
        prompt: &str,
        labels: &[String],
        checked: &[bool],
    ) -> Result<Vec<usize>, ToolError>;
    /// Yes/no with a default.
    ///
    /// # Errors
    ///
    /// Returns a [`ToolError`] on I/O failure or user abort.
    fn confirm(&self, prompt: &str, default: bool) -> Result<bool, ToolError>;
    /// Multi-line text seeded with `seed` (via `$EDITOR`); returns the seed unchanged
    /// if the editor is closed without saving.
    ///
    /// # Errors
    ///
    /// Returns a [`ToolError`] on I/O failure or user abort.
    fn editor(&self, prompt: &str, seed: &str) -> Result<String, ToolError>;
}

/// Restore the terminal cursor on Ctrl-C, then exit 130.
///
/// `dialoguer` hides the cursor for the duration of a `Select` or `MultiSelect` and shows
/// it again on the way out. SIGINT's default action kills the process before that runs, so
/// without this handler Ctrl-C on a wizard menu leaves the shell with an invisible cursor
/// until the operator runs `reset`: the stream carries `ESC[?25l` and never `ESC[?25h`.
///
/// Uses the `signal` feature of the `tokio` the tool already depends on, on its own
/// current-thread runtime in a background thread: the CLI core is synchronous and blocked
/// reading a key, so there is no ambient runtime to spawn onto.
///
/// Registering the handler also stops SIGINT killing the process outright, which turns
/// Ctrl-C into the ordinary abort the wizard already reports: the blocked read returns
/// `EINTR`, `dialoguer` surfaces it, and the run ends via [`abort`] with "wizard aborted:
/// …" and exit 1, its own cleanup restoring the cursor. This thread gives that path a
/// moment to happen and only forces the exit if it does not, so the exit code cannot race
/// between 1 and 130 for the same keystroke. Showing the cursor first is idempotent.
///
/// Cursor visibility is a DEC private mode, not a termios flag, which is why the shell's
/// own `tcsetattr` on regaining the foreground restores echo but not this.
fn restore_cursor_on_interrupt() {
    /// How long the main thread gets to report the abort itself before this forces the
    /// exit. Long enough that the main thread usually wins, short enough that a wedged
    /// prompt still dies promptly on Ctrl-C.
    const GRACE: std::time::Duration = std::time::Duration::from_millis(300);
    std::thread::spawn(|| {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        if rt.block_on(tokio::signal::ctrl_c()).is_ok() {
            let _ = console::Term::stderr().show_cursor();
            std::thread::sleep(GRACE);
            // Still here: the main thread did not notice the interrupted read, so Ctrl-C
            // would otherwise appear to do nothing. 130 is "terminated by SIGINT".
            std::process::exit(130);
        }
    });
}

/// Show the terminal cursor again. Idempotent, and a no-op off a terminal.
///
/// Called on every exit from the wizard, whatever the outcome. `dialoguer` hides the
/// cursor per menu and restores it per menu, so an abort mid-menu — the Ctrl-C case — can
/// leave it hidden. The signal thread alone cannot undo that: it races the main thread,
/// which usually wins.
pub fn restore_cursor() {
    let _ = console::Term::stderr().show_cursor();
}

/// Require an interactive terminal (stdin + stderr). The wizard is interactive;
/// headless callers use `config init` + the plain commands.
///
/// On success this also arms the Ctrl-C cursor restore, so the guard and the handler
/// cannot come apart: the wizard is the only surface that hides the cursor, and this is
/// the one gate it passes through. (Named in prose, not as an intra-doc link: the target is
/// private, and a public item linking to a private one fails the documentation build.)
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when stdin or stderr is not a TTY.
pub fn require_tty() -> Result<(), ToolError> {
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        restore_cursor_on_interrupt();
        Ok(())
    } else {
        Err(ToolError::user(
            "the wizard needs an interactive terminal; for headless setup use \
             `gdi-dataset-tool config init` + the GDI_TOOL__ env vars, then `build`/`pack`/`upload`",
        ))
    }
}

/// Map a dialoguer error (incl. Ctrl-C/Esc) to a clean tool error.
fn abort(e: &dialoguer::Error) -> ToolError {
    ToolError::user(format!("wizard aborted: {e}"))
}

/// Tab-completion over the local filesystem for the path prompts.
///
/// Three behaviours, layered like a shell's:
/// 1. **Extend** — a single match completes fully (a directory gets its trailing `/`,
///    so the next Tab descends into it); several matches extend to their longest common
///    prefix. Dot-files are offered only once the operator has typed the dot.
/// 2. **List** — when nothing extends and several candidates remain, the first Tab
///    prints them above the prompt (bash's double-Tab), then reprints the prompt line
///    so dialoguer's in-place editing continues on the same row.
/// 3. **Cycle** — further Tabs substitute each candidate in turn, wrapping; any edit
///    resets the cycle.
///
/// Interior mutability because [`dialoguer::Completion::get`] takes `&self`; the prompt
/// text and default are carried so the list step can reprint a byte-identical prompt
/// line via the same theme dialoguer rendered it with (dialoguer only clears/rewrites
/// the typed chars on Tab and never repaints the prompt, so whoever scrolls it away
/// must redraw it).
struct PathCompletion {
    /// The prompt text, exactly as passed to the `Input` builder.
    prompt: String,
    /// The prompt's default value, when one was shown.
    default: Option<String>,
    /// The cycle state; `None` until a list/cycle interaction begins.
    state: RefCell<Option<CycleState>>,
    /// Whether the screen is in the detached layout: the prompt on its own row and the
    /// input starting at column 0 of the row below. Entered (one way, per prompt) the
    /// first time a completed path is too wide to share the prompt's row — see
    /// [`Self::prepare_substitution_redraw`].
    detached: std::cell::Cell<bool>,
}

/// Where a list/cycle interaction stands for one typed stem.
struct CycleState {
    /// The stem the candidates were computed for (the input at list time).
    stem: String,
    /// The full candidate paths, sorted.
    matches: Vec<String>,
    /// The index of the next candidate to emit.
    next: usize,
    /// What the previous Tab emitted — cycling continues only while the input still
    /// equals it (any edit falls back to a fresh computation).
    last_emitted: Option<String>,
}

impl PathCompletion {
    fn new(prompt: &str, default: Option<&str>) -> Self {
        Self {
            prompt: prompt.to_owned(),
            default: default.map(str::to_owned),
            state: RefCell::new(None),
            detached: std::cell::Cell::new(false),
        }
    }

    /// Print the candidate list above the prompt, then reprint the prompt + input —
    /// only on a real terminal (the scripted twin never routes here, and unit tests
    /// exercise the state machine without terminal output).
    fn show_list(&self, input: &str, matches: &[String]) {
        use std::io::IsTerminal as _;
        const MAX_LISTED: usize = 30;
        if !std::io::stderr().is_terminal() {
            return;
        }
        let names: Vec<String> = matches
            .iter()
            .take(MAX_LISTED)
            .map(|m| {
                m.rsplit_once('/')
                    .map_or(m.as_str(), |(head, tail)| {
                        // A directory candidate ends in '/', splitting to an empty tail;
                        // show `name/` in that case.
                        if tail.is_empty() { head } else { tail }
                    })
                    .to_owned()
            })
            .collect();
        let more = matches.len().saturating_sub(MAX_LISTED);
        let listing = if more > 0 {
            format!("{}  ... and {more} more", names.join("  "))
        } else {
            names.join("  ")
        };
        // A newline first (the cursor sits at the end of the input), the list, then a
        // faithful reprint. Contiguous (prompt + input on one row) while they fit;
        // otherwise the detached layout — prompt on its own row, input at column 0
        // below — the one layout whose later redraws dialoguer's single-row clear
        // cannot corrupt (see `prepare_substitution_redraw`).
        eprintln!();
        eprintln!("{listing}");
        let cols = terminal_cols();
        let fits = cols == 0
            || extra_wrapped_rows(
                console::measure_text_width(&self.rendered_prompt())
                    + console::measure_text_width(input),
                cols,
            ) == 0;
        if self.detached.get() || !fits {
            self.detached.set(true);
            eprintln!("{}", self.rendered_prompt());
            eprint!("{input}");
        } else {
            eprint!("{}{input}", self.rendered_prompt());
        }
    }

    /// The prompt line exactly as dialoguer rendered it (same theme, same glyphs),
    /// for the list step's reprint and for width math.
    fn rendered_prompt(&self) -> String {
        let mut rendered = String::new();
        let theme = dialoguer::theme::ColorfulTheme::default();
        let _ = dialoguer::theme::Theme::format_input_prompt(
            &theme,
            &mut rendered,
            &self.prompt,
            self.default.as_deref(),
        );
        rendered
    }

    /// Put the screen in a state dialoguer's substitution redraw renders correctly.
    ///
    /// After `get` returns `Some`, dialoguer erases the old input with
    /// `ESC[{len}D` + `ESC[0K` — a cursor-left that cannot cross a soft-wrapped row
    /// and an erase confined to that row. Over an input that wrapped (a long completed
    /// path) that clears only the bottom row, leaving the head of the old candidate on
    /// the first row while the replacement lands on the row below.
    ///
    /// The detached layout avoids that: the first time a substitution involves a
    /// wrapped input, erase the whole prompt+input region and reprint the prompt on
    /// its own row, leaving the cursor at column 0 of the row below — dialoguer's
    /// bounded left-move then lands exactly at the input start, its erase clears an
    /// empty row, and its write fills clean rows. Every later pass only has to clear
    /// the old input's own rows (the input now starts at column 0, so the row count is
    /// exact), and the prompt row above never moves — no drift, no remnants.
    fn prepare_substitution_redraw(&self, old_input: &str) {
        use std::io::IsTerminal as _;
        if !std::io::stderr().is_terminal() {
            return;
        }
        let term = console::Term::stderr();
        let cols = terminal_cols();
        if cols == 0 {
            return;
        }
        let old_width = console::measure_text_width(old_input);
        if self.detached.get() {
            // Input occupies `1 + extra` rows starting at column 0; the cursor sits at
            // its end (bottom row). Clear the input rows bottom-up; `clear_line` leaves
            // the cursor at column 0 of the top input row, where dialoguer expects it.
            let extra = extra_wrapped_rows(old_width, cols);
            if extra == 0 {
                return; // single-row input: dialoguer's own clear is sufficient
            }
            let _ = term.clear_line();
            for _ in 0..extra {
                let _ = term.move_cursor_up(1);
                let _ = term.clear_line();
            }
        } else {
            let prompt_width = console::measure_text_width(&self.rendered_prompt());
            let extra = extra_wrapped_rows(prompt_width + old_width, cols);
            if extra == 0 {
                return; // fits beside the prompt: dialoguer handles it
            }
            // Enter the detached layout: clear the contiguous prompt+input region
            // bottom-up, reprint the prompt alone, and leave the cursor on the fresh
            // row below it.
            let _ = term.clear_line();
            for _ in 0..extra {
                let _ = term.move_cursor_up(1);
                let _ = term.clear_line();
            }
            eprintln!("{}", self.rendered_prompt());
            self.detached.set(true);
        }
        let _ = std::io::Write::flush(&mut std::io::stderr());
    }
}

/// The stderr terminal's column count, `0` when unknown.
fn terminal_cols() -> usize {
    usize::from(console::Term::stderr().size().1)
}

/// Rows beyond the first that `total_width` printed characters occupy on a `cols`-wide
/// terminal. The `-1` keeps the exact-fit case — where the cursor rests at the margin
/// pending wrap — on one row.
fn extra_wrapped_rows(total_width: usize, cols: usize) -> usize {
    total_width.saturating_sub(1) / cols
}

impl dialoguer::Completion for PathCompletion {
    fn get(&self, input: &str) -> Option<String> {
        let mut state = self.state.borrow_mut();
        // Mid-cycle: the input is exactly what the previous Tab emitted → next match.
        if let Some(s) = state.as_mut()
            && s.last_emitted.as_deref() == Some(input)
            && !s.matches.is_empty()
        {
            let candidate = s.matches[s.next % s.matches.len()].clone();
            s.next = (s.next + 1) % s.matches.len();
            s.last_emitted = Some(candidate.clone());
            self.prepare_substitution_redraw(input);
            return Some(candidate);
        }
        // Fresh input: extend when something extends.
        let (extended, matches) = complete_path(input);
        if let Some(longer) = extended {
            *state = None;
            self.prepare_substitution_redraw(input);
            return Some(longer);
        }
        if matches.len() < 2 {
            *state = None;
            return None;
        }
        // Nothing extends and several candidates remain: list once per stem, then cycle.
        match state.as_mut() {
            Some(s) if s.stem == input => {
                let candidate = s.matches.first()?.clone();
                s.next = 1 % s.matches.len();
                s.last_emitted = Some(candidate.clone());
                self.prepare_substitution_redraw(input);
                Some(candidate)
            }
            _ => {
                self.show_list(input, &matches);
                *state = Some(CycleState {
                    stem: input.to_owned(),
                    matches,
                    next: 0,
                    last_emitted: None,
                });
                None
            }
        }
    }
}

/// The extension of `input` (when something longer can be offered) plus the full sorted
/// candidate list. A single match completes fully (a directory keeps its trailing `/`),
/// several extend to their longest common prefix; the list backs the shell-style
/// listing + cycling when no extension exists.
fn complete_path(input: &str) -> (Option<String>, Vec<String>) {
    let (dir_prefix, partial) = match input.rsplit_once('/') {
        Some((dir, rest)) => (format!("{dir}/"), rest),
        None => (String::new(), input),
    };
    let read_from = if dir_prefix.is_empty() {
        "."
    } else {
        dir_prefix.as_str()
    };
    let Ok(entries) = std::fs::read_dir(read_from) else {
        return (None, Vec::new());
    };
    let mut matches: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let hidden = name.starts_with('.') && !partial.starts_with('.');
            if hidden || !name.starts_with(partial) {
                return None;
            }
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            Some(if is_dir {
                format!("{dir_prefix}{name}/")
            } else {
                format!("{dir_prefix}{name}")
            })
        })
        .collect();
    // The same natural order the directory multi-select uses (`chr2` before `chr10`):
    // both list the same files, so a lexical cycle here would contradict the picker the
    // operator has just seen.
    matches.sort_by(|a, b| crate::wizard::author::natural_cmp(a, b));
    let completed = match matches.as_slice() {
        [] => return (None, matches),
        [only] => only.clone(),
        many => longest_common_prefix(many),
    };
    let extended = (completed.len() > input.len()).then_some(completed);
    (extended, matches)
}

/// The longest prefix (on `char` boundaries) shared by every string in `items`.
fn longest_common_prefix(items: &[String]) -> String {
    let Some(first) = items.first() else {
        return String::new();
    };
    let mut prefix = String::new();
    for (i, c) in first.char_indices() {
        let next = i + c.len_utf8();
        let head = first.get(..next);
        if items.iter().all(|s| s.get(..next) == head) {
            prefix.push(c);
        } else {
            break;
        }
    }
    prefix
}

/// The real terminal prompter, backed by `dialoguer`.
pub struct DialoguerPrompter;

impl Prompter for DialoguerPrompter {
    fn input(
        &self,
        prompt: &str,
        default: Option<&str>,
        allow_empty: bool,
    ) -> Result<String, ToolError> {
        let theme = dialoguer::theme::ColorfulTheme::default();
        let mut b = dialoguer::Input::<String>::with_theme(&theme)
            .with_prompt(prompt)
            .allow_empty(allow_empty);
        if let Some(d) = default {
            b = b.default(d.to_owned());
        }
        b.interact_text().map_err(|e| abort(&e))
    }

    fn input_validated(
        &self,
        prompt: &str,
        default: Option<&str>,
        validate: &dyn Fn(&str) -> Result<(), String>,
    ) -> Result<String, ToolError> {
        let theme = dialoguer::theme::ColorfulTheme::default();
        // `allow_empty`: the validator decides whether a blank answer is acceptable.
        // Dialoguer's own empty-input refusal in front of it would leave every "blank to
        // skip" prompt (the afSource reference, the cohort size) skippable by the scripted
        // prompter but never at a real terminal.
        let mut b = dialoguer::Input::<String>::with_theme(&theme)
            .with_prompt(prompt)
            .allow_empty(true);
        if let Some(d) = default {
            b = b.default(d.to_owned());
        }
        b.validate_with(|s: &String| validate(s))
            .interact_text()
            .map_err(|e| abort(&e))
    }

    fn input_path(
        &self,
        prompt: &str,
        default: Option<&str>,
        validate: &dyn Fn(&str) -> Result<(), String>,
    ) -> Result<String, ToolError> {
        let theme = dialoguer::theme::ColorfulTheme::default();
        let completion = PathCompletion::new(prompt, default);
        let mut b = dialoguer::Input::<String>::with_theme(&theme)
            .with_prompt(prompt)
            .allow_empty(true)
            .completion_with(&completion);
        if let Some(d) = default {
            b = b.default(d.to_owned());
        }
        b.validate_with(|s: &String| validate(s))
            .interact_text()
            .map_err(|e| abort(&e))
    }

    fn secret(&self, prompt: &str) -> Result<String, ToolError> {
        let theme = dialoguer::theme::ColorfulTheme::default();
        dialoguer::Password::with_theme(&theme)
            .with_prompt(prompt)
            .allow_empty_password(true)
            .interact()
            .map_err(|e| abort(&e))
    }

    fn select(&self, prompt: &str, labels: &[String], default: usize) -> Result<usize, ToolError> {
        let theme = dialoguer::theme::ColorfulTheme::default();
        dialoguer::Select::with_theme(&theme)
            .with_prompt(prompt)
            .items(labels)
            .default(default)
            .interact()
            .map_err(|e| abort(&e))
    }

    fn multiselect(
        &self,
        prompt: &str,
        labels: &[String],
        checked: &[bool],
    ) -> Result<Vec<usize>, ToolError> {
        let theme = dialoguer::theme::ColorfulTheme::default();
        dialoguer::MultiSelect::with_theme(&theme)
            .with_prompt(prompt)
            .items(labels)
            .defaults(checked)
            .interact()
            .map_err(|e| abort(&e))
    }

    fn confirm(&self, prompt: &str, default: bool) -> Result<bool, ToolError> {
        let theme = dialoguer::theme::ColorfulTheme::default();
        dialoguer::Confirm::with_theme(&theme)
            .with_prompt(prompt)
            .default(default)
            .interact()
            .map_err(|e| abort(&e))
    }

    fn editor(&self, prompt: &str, seed: &str) -> Result<String, ToolError> {
        crate::output::note(prompt);
        match dialoguer::Editor::new().edit(seed) {
            Ok(Some(text)) => Ok(text),
            Ok(None) => Ok(seed.to_owned()), // editor closed without saving → keep seed
            Err(e) => Err(ToolError::user(format!("wizard editor failed: {e}"))),
        }
    }
}

/// A scripted prompter for tests: pops pre-loaded answers in call order. An empty
/// queue yields an error (never a panic), so a mis-scripted flow fails the test cleanly.
pub struct ScriptedPrompter {
    /// Every prompt string this prompter was asked, in order — including each menu's
    /// labels. Recorded so a test can assert properties of the prompts the wizard really
    /// reaches, rather than of a hand-kept list that drifts from them.
    seen: RefCell<Vec<String>>,
    /// Each `select` as (prompt, pre-selected index). The pre-selection is what an operator
    /// gets by pressing Enter, so it is behaviour, not decoration, and a test can assert
    /// on it.
    seen_defaults: RefCell<Vec<(String, usize)>>,
    /// Each `multiselect` as (prompt, pre-checked flags). Same argument as
    /// [`Self::seen_defaults`]: what is ticked when the menu opens is what an operator
    /// gets by pressing Enter, and for the legislation menu that pre-tick is derived from
    /// the profile and the sources — a rule only observable if the harness keeps `checked`.
    seen_multiselect_defaults: RefCell<Vec<(String, Vec<bool>)>>,
    inputs: RefCell<VecDeque<String>>,
    secrets: RefCell<VecDeque<String>>,
    selects: RefCell<VecDeque<usize>>,
    multiselects: RefCell<VecDeque<Vec<usize>>>,
    confirms: RefCell<VecDeque<bool>>,
    editors: RefCell<VecDeque<String>>,
}

impl ScriptedPrompter {
    /// An empty scripted prompter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: RefCell::new(Vec::new()),
            seen_defaults: RefCell::new(Vec::new()),
            seen_multiselect_defaults: RefCell::new(Vec::new()),
            inputs: RefCell::new(VecDeque::new()),
            secrets: RefCell::new(VecDeque::new()),
            selects: RefCell::new(VecDeque::new()),
            multiselects: RefCell::new(VecDeque::new()),
            confirms: RefCell::new(VecDeque::new()),
            editors: RefCell::new(VecDeque::new()),
        }
    }

    /// Note a prompt (and any menu labels) that was put to this prompter.
    fn record(&self, prompt: &str, labels: &[String]) {
        let mut seen = self.seen.borrow_mut();
        seen.push(prompt.to_owned());
        seen.extend(labels.iter().cloned());
    }

    /// The pre-selected index each `select` was rendered with, by prompt.
    #[must_use]
    pub fn seen_select_defaults(&self) -> Vec<(String, usize)> {
        self.seen_defaults.borrow().clone()
    }

    /// The pre-checked flags each `multiselect` was rendered with, by prompt.
    #[must_use]
    pub fn seen_multiselect_defaults(&self) -> Vec<(String, Vec<bool>)> {
        self.seen_multiselect_defaults.borrow().clone()
    }

    /// Every prompt string and menu label this prompter was asked, in order.
    ///
    /// Lets a test assert over the prompts the wizard actually reaches on a given path —
    /// the alternative, a hand-kept list of prompt literals, is a second copy of the same
    /// fact and drifts from the first the moment a prompt is reworded.
    #[must_use]
    pub fn seen_prompts(&self) -> Vec<String> {
        self.seen.borrow().clone()
    }
    /// Queue free-text answers, consumed by `input`, `input_validated` and `input_path`;
    /// `editor` and `secret` draw from their own queues ([`Self::with_editors`],
    /// [`Self::with_secrets`]).
    #[must_use]
    pub fn with_inputs(self, v: Vec<&str>) -> Self {
        *self.inputs.borrow_mut() = v.into_iter().map(str::to_owned).collect();
        self
    }
    /// Queue `secret` answers.
    #[must_use]
    pub fn with_secrets(self, v: Vec<&str>) -> Self {
        *self.secrets.borrow_mut() = v.into_iter().map(str::to_owned).collect();
        self
    }
    /// Queue `select` answers (indices).
    #[must_use]
    pub fn with_selects(self, v: Vec<usize>) -> Self {
        *self.selects.borrow_mut() = v.into();
        self
    }
    /// Queue `multiselect` answers.
    #[must_use]
    pub fn with_multiselects(self, v: Vec<Vec<usize>>) -> Self {
        *self.multiselects.borrow_mut() = v.into();
        self
    }
    /// Queue `confirm` answers.
    #[must_use]
    pub fn with_confirms(self, v: Vec<bool>) -> Self {
        *self.confirms.borrow_mut() = v.into();
        self
    }
    /// Queue `editor` answers.
    #[must_use]
    pub fn with_editors(self, v: Vec<&str>) -> Self {
        *self.editors.borrow_mut() = v.into_iter().map(str::to_owned).collect();
        self
    }
}

impl Default for ScriptedPrompter {
    fn default() -> Self {
        Self::new()
    }
}

fn pop<T>(q: &RefCell<VecDeque<T>>, what: &str) -> Result<T, ToolError> {
    q.borrow_mut()
        .pop_front()
        .ok_or_else(|| ToolError::user(format!("scripted prompter ran dry on {what}")))
}

/// Substitute the prompt's default for an empty scripted answer, as the real prompter does.
///
/// `dialoguer` returns the default when the operator presses Enter, so the harness must do
/// the same: a scripted "" that reached the validator as an empty string would leave the
/// commonest interaction in a wizard — pressing Enter — untestable, and a prompt offering
/// the wrong default indistinguishable from one offering the right one.
fn or_default(answer: String, default: Option<&str>) -> String {
    match default {
        Some(d) if answer.is_empty() => d.to_owned(),
        _ => answer,
    }
}

impl Prompter for ScriptedPrompter {
    fn input(
        &self,
        prompt: &str,
        default: Option<&str>,
        _allow_empty: bool,
    ) -> Result<String, ToolError> {
        self.record(prompt, &[]);
        Ok(or_default(pop(&self.inputs, "input")?, default))
    }
    fn input_validated(
        &self,
        prompt: &str,
        default: Option<&str>,
        validate: &dyn Fn(&str) -> Result<(), String>,
    ) -> Result<String, ToolError> {
        self.record(prompt, &[]);
        let v = or_default(pop(&self.inputs, "input_validated")?, default);
        validate(&v).map_err(ToolError::user)?;
        Ok(v)
    }
    fn input_path(
        &self,
        prompt: &str,
        default: Option<&str>,
        validate: &dyn Fn(&str) -> Result<(), String>,
    ) -> Result<String, ToolError> {
        self.record(prompt, &[]);
        let v = or_default(pop(&self.inputs, "input_path")?, default);
        validate(&v).map_err(ToolError::user)?;
        Ok(v)
    }
    fn secret(&self, prompt: &str) -> Result<String, ToolError> {
        self.record(prompt, &[]);
        pop(&self.secrets, "secret")
    }
    fn select(&self, prompt: &str, labels: &[String], default: usize) -> Result<usize, ToolError> {
        self.record(prompt, labels);
        self.seen_defaults
            .borrow_mut()
            .push((prompt.to_owned(), default));
        pop(&self.selects, "select")
    }
    fn multiselect(
        &self,
        prompt: &str,
        labels: &[String],
        checked: &[bool],
    ) -> Result<Vec<usize>, ToolError> {
        self.record(prompt, labels);
        self.seen_multiselect_defaults
            .borrow_mut()
            .push((prompt.to_owned(), checked.to_vec()));
        pop(&self.multiselects, "multiselect")
    }
    fn confirm(&self, prompt: &str, _default: bool) -> Result<bool, ToolError> {
        self.record(prompt, &[]);
        pop(&self.confirms, "confirm")
    }
    fn editor(&self, prompt: &str, _seed: &str) -> Result<String, ToolError> {
        self.record(prompt, &[]);
        pop(&self.editors, "editor")
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn scripted_prompter_returns_answers_in_order() {
        let p = ScriptedPrompter::new()
            .with_inputs(vec!["UTARTU", "My dataset", "data/x.vcf"])
            .with_secrets(vec!["AKIA"])
            .with_selects(vec![1])
            .with_confirms(vec![true])
            .with_multiselects(vec![vec![0, 2]]);
        assert_eq!(p.input("org", Some("ORG"), false).unwrap(), "UTARTU");
        assert_eq!(
            p.select("assembly", &["GRCh37".into(), "GRCh38".into()], 0)
                .unwrap(),
            1
        );
        assert_eq!(p.input("title", None, false).unwrap(), "My dataset");
        assert_eq!(
            p.input_path("vcf", None, &|_| Ok(())).unwrap(),
            "data/x.vcf",
            "input_path draws from the same queue as the other text prompts"
        );
        assert_eq!(p.secret("key").unwrap(), "AKIA");
        assert!(p.confirm("ok?", false).unwrap());
        assert_eq!(
            p.multiselect(
                "k",
                &["a".into(), "b".into(), "c".into()],
                &[true, true, true]
            )
            .unwrap(),
            vec![0, 2]
        );
    }

    #[test]
    fn scripted_prompter_runs_dry_errors() {
        let p = ScriptedPrompter::new();
        assert!(
            p.input("x", None, false).is_err(),
            "empty script must error, not panic"
        );
        assert!(p.secret("s").is_err(), "the secret queue is its own queue");
    }

    #[test]
    fn input_validated_uses_scripted_value_and_validator() {
        // ScriptedPrompter applies the validator to the scripted value (so flow
        // tests exercise the resolver wiring); a value the validator rejects errors.
        let ok = ScriptedPrompter::new().with_inputs(vec!["GRCh38"]);
        assert_eq!(
            ok.input_validated("assembly", None, &|s| if s == "GRCh38" {
                Ok(())
            } else {
                Err("bad".into())
            })
            .unwrap(),
            "GRCh38"
        );
        let bad = ScriptedPrompter::new().with_inputs(vec!["hg38"]);
        assert!(
            bad.input_validated("assembly", None, &|s| if s == "GRCh38" {
                Ok(())
            } else {
                Err("bad".into())
            })
            .is_err()
        );
        // `input_path` validates the same way, so a scripted missing path fails the test
        // that scripted it rather than silently reaching the flow.
        let bad_path = ScriptedPrompter::new().with_inputs(vec!["nope.vcf"]);
        assert!(
            bad_path
                .input_path("vcf", None, &|s| if s == "nope.vcf" {
                    Err("missing".into())
                } else {
                    Ok(())
                })
                .is_err()
        );
    }

    /// Tab-completion completes a unique match fully (a directory with its `/`), several
    /// matches to their common prefix, and offers no extension when nothing is longer —
    /// while still reporting the candidate list that backs listing + cycling.
    #[test]
    fn path_completion_completes_against_the_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir(root.join("chromosomes")).unwrap();
        std::fs::File::create_new(root.join("chr1.vcf.gz")).unwrap();
        std::fs::File::create_new(root.join("chr2.vcf.gz")).unwrap();
        std::fs::File::create_new(root.join(".hidden.vcf")).unwrap();
        let base = format!("{}/", root.display());

        // Several matches: the common prefix.
        assert_eq!(
            complete_path(&format!("{base}ch")).0.as_deref(),
            Some(format!("{base}chr").as_str())
        );
        // A unique file completes fully.
        assert_eq!(
            complete_path(&format!("{base}chr1")).0.as_deref(),
            Some(format!("{base}chr1.vcf.gz").as_str())
        );
        // A unique directory completes with its trailing slash.
        assert_eq!(
            complete_path(&format!("{base}chro")).0.as_deref(),
            Some(format!("{base}chromosomes/").as_str())
        );
        // Nothing longer to offer: the input already names the file.
        assert_eq!(complete_path(&format!("{base}chr1.vcf.gz")).0, None);
        // Dot-files stay hidden until the dot is typed.
        let (extended, matches) = complete_path(&format!("{base}x"));
        assert_eq!(extended, None, "no visible entry starts with x");
        assert!(matches.is_empty());
        assert_eq!(
            complete_path(&format!("{base}.h")).0.as_deref(),
            Some(format!("{base}.hidden.vcf").as_str())
        );
        // A directory that does not exist offers nothing.
        assert_eq!(complete_path(&format!("{base}missing/ch")).0, None);
    }

    /// The shell layer over completion: when nothing extends, the first Tab lists (a
    /// state transition; the print itself is TTY-gated) and further Tabs cycle through
    /// the candidates, wrapping; any edit resets the cycle.
    #[test]
    fn path_completion_lists_then_cycles_when_nothing_extends() {
        use dialoguer::Completion as _;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::File::create_new(root.join("chr1.vcf.gz")).unwrap();
        std::fs::File::create_new(root.join("chr2.vcf.gz")).unwrap();
        let base = format!("{}/", root.display());
        let stem = format!("{base}chr"); // the common prefix: nothing extends past it
        let one = format!("{base}chr1.vcf.gz");
        let two = format!("{base}chr2.vcf.gz");

        let c = PathCompletion::new("VCF file", None);
        // Tab 1 on the stem: the list step (no substitution yet).
        assert_eq!(c.get(&stem), None);
        // Tab 2: the first candidate; Tab 3: the second; Tab 4: wraps to the first.
        assert_eq!(c.get(&stem).as_deref(), Some(one.as_str()));
        assert_eq!(c.get(&one).as_deref(), Some(two.as_str()));
        assert_eq!(c.get(&two).as_deref(), Some(one.as_str()));
        // An edit mid-cycle resets: a fresh stem extends normally again.
        assert_eq!(
            c.get(&format!("{base}chr1")).as_deref(),
            Some(one.as_str()),
            "an edited input leaves the cycle and completes normally"
        );
    }

    /// The wrap-row math behind the substitution redraw: exact fit stays one row
    /// (the cursor rests at the margin pending wrap), one past it wraps.
    #[test]
    fn extra_wrapped_rows_counts_rows_beyond_the_first() {
        assert_eq!(extra_wrapped_rows(0, 80), 0);
        assert_eq!(extra_wrapped_rows(79, 80), 0);
        assert_eq!(
            extra_wrapped_rows(80, 80),
            0,
            "exact fit pends at the margin"
        );
        assert_eq!(extra_wrapped_rows(81, 80), 1);
        assert_eq!(extra_wrapped_rows(160, 80), 1);
        assert_eq!(extra_wrapped_rows(161, 80), 2);
    }

    #[test]
    fn longest_common_prefix_respects_char_boundaries() {
        assert_eq!(
            longest_common_prefix(&["chr1.vcf".into(), "chr10.vcf".into()]),
            "chr1"
        );
        assert_eq!(
            longest_common_prefix(&["äpple".into(), "äpfel".into()]),
            "äp"
        );
        assert_eq!(longest_common_prefix(&["a".into(), "b".into()]), "");
        assert_eq!(longest_common_prefix(&[]), "");
    }
}
