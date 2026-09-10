//! Greenfield `package.yaml` authoring by template-fill: the model is deserialize-only,
//! so this fills a commented YAML template, as `cmd_init` does, rather than serializing.
//! The result is parsed back and validated as a whole.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use gdi_node_standalone_core::convert::{
    ConvertOptions, preview_vcf_with_progress, read_header_hints, read_header_populations,
};
use gdi_node_standalone_core::model::PackageYaml;
use gdi_node_standalone_core::validate_pkg::{
    MAX_CREATOR_NAME_LEN, MAX_DESCRIPTION_LEN, MAX_TITLE_LEN, validate_package_collect_all,
};

use crate::ToolError;
use crate::wizard::fields;
use crate::wizard::prompts::Prompter;

/// The collected, validated field values that [`render_template`] turns into YAML.
#[derive(Debug, Clone)]
pub struct AuthorValues {
    /// `metadata.prefix` (`GOE`/`GDI`).
    pub prefix: String,
    /// `metadata.org`.
    pub org: String,
    /// `metadata.catalog`.
    pub catalog: String,
    /// `metadata.title` (plain).
    pub title: String,
    /// `metadata.description` (plain).
    pub description: String,
    /// Full `metadata.accessRights` IRI.
    pub access_rights_iri: String,
    /// Full `metadata.license` IRI.
    pub license_iri: String,
    /// First `metadata.creator[].name`.
    pub creator: String,
    /// `metadata.healthCategory` IRIs (1..n, all from the vendored closed set).
    pub health_category_iris: Vec<String>,
    /// `metadata.conformsTo` IRIs (0..n, all from the vendored closed set). Empty omits
    /// the field; there is no node-level default.
    pub conforms_to_iris: Vec<String>,
    /// `metadata.applicableLegislation` IRIs (1..n, de-duplicated, in the order the
    /// operator chose them). The EHDS ELI is pre-checked but removable. The GDPR entry's
    /// pre-check is the data-derived `gdpr_default` rule. Further ELIs are free entry.
    pub applicable_legislation: Vec<String>,
    /// `metadata.keywords`.
    pub keywords: Vec<String>,
    /// `metadata.numberOfUniqueIndividuals`.
    pub number_of_unique_individuals: Option<u64>,
    /// `config.afSource`.
    pub af_source: Option<String>,
    /// `config.afSourceReference`.
    pub af_source_reference: Option<String>,
    /// The source VCF paths, `files[VCF].files[]` in order — one per file, and a
    /// per-chromosome set is the common plural.
    pub vcf_paths: Vec<String>,
    /// `files[VCF].reference` (assembly).
    pub assembly: String,
    /// `config.blockRange`.
    pub block_range: u32,
    /// `config.minAlleleCount`.
    pub min_allele_count: u32,
    /// Whether to mark this a synthetic dataset (adds `metadata.type`).
    pub synthetic: bool,
}

/// The outcome of authoring: where the package.yaml was written, and what the caller
/// should persist on the operator's behalf.
#[derive(Debug, Clone)]
pub struct AuthorResult {
    /// The written `package.yaml` path.
    pub path: PathBuf,
    /// An `org` the operator typed and asked to have remembered in the profile. Authoring
    /// has no config handle, so the wizard orchestrator stores it.
    pub org_to_store: Option<String>,
}

/// Context above the build-time k-anonymity floor prompt.
///
/// It states the unit at the point of choice. The alleles-vs-individuals caveat otherwise
/// appears only in the node's `node.example.toml`, which a provider running this tool
/// never opens — so someone typing `5` would reasonably believe they had protected five
/// people rather than about three. The collapse-to-Total detail lives in the floor-impact
/// report printed right after, where it is concrete numbers about the operator's own data
/// instead of prose.
const FLOOR_NOTE: &str = "Small allele counts can be withheld at build time \
     (minAlleleCount). The unit is ALLELES, not people: a homozygous carrier counts 2, \
     so 5 ~ three people.";

/// The floor prompt itself, short now that [`FLOOR_NOTE`] carries the context.
const FLOOR_PROMPT: &str = "Withhold rows with allele count below (0 = publish everything)";

/// Ask for the build-time `minAlleleCount`, defaulting to `0` (no suppression).
///
/// # Errors
///
/// Returns a [`ToolError`] when the prompt is aborted or the answer is not a `u32`.
fn prompt_min_allele_count(p: &dyn Prompter) -> Result<u32, ToolError> {
    crate::output::always(FLOOR_NOTE);
    let raw = p.input_validated(FLOOR_PROMPT, Some("0"), &|s| {
        parse_floor(s).map(|_| ()).map_err(|e| e.message)
    })?;
    parse_floor(&raw)
}

/// Parse a floor answer: a non-negative integer; empty means `0`.
fn parse_floor(s: &str) -> Result<u32, ToolError> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(0);
    }
    t.parse::<u32>().map_err(|_| {
        ToolError::user(format!(
            "minAlleleCount must be a non-negative integer: {t:?}"
        ))
    })
}

/// Print what the chosen floor would withhold from `vcf`: rows dropped below it, rows
/// lost to the coherence collapse, and the populations that survive.
///
/// Best-effort and never fatal: the VCF already previewed cleanly above, and a floor
/// report is not worth failing the authoring flow over. This is the one record scan the
/// authoring stage runs, so it draws the same byte bar `preview` and `build` do — a
/// whole-chromosome file is minutes of silence otherwise. With several sources only the
/// first is sampled (`total_sources` says so in the line); `preview --floor-impact` is the
/// per-file question.
fn report_floor_impact(vcf: &Path, assembly: &str, min_allele_count: u32, total_sources: usize) {
    if min_allele_count == 0 {
        crate::output::progress(
            "minAlleleCount 0: no rows will be suppressed at build time (the node may still \
             apply its own floor)",
        );
        return;
    }
    let opts = ConvertOptions {
        assembly: assembly.to_owned(),
        block_range: 0,
        min_allele_count,
    };
    let scope = if total_sources > 1 {
        format!(
            " (sampled on {}: the first of {total_sources} sources; the build applies the floor to all)",
            crate::output::Untrusted(&file_name_of(vcf))
        )
    } else {
        String::new()
    };
    let prog = crate::progress::ConvertProgress::for_paths(
        std::slice::from_ref(&vcf.to_path_buf()),
        crate::progress::active(),
    );
    let report = preview_vcf_with_progress(vcf, &opts, &|n| prog.inc(0, n));
    prog.finish();
    match report {
        Ok(r) => crate::output::progress(&format!(
            "at minAlleleCount {min_allele_count}{scope}: {} row(s) below the floor, {} more \
             removed by collapsing {} variant(s) to Total; populations that survive: {}",
            r.suppression.rows_below_floor,
            r.suppression.rows_collapsed_to_total,
            r.suppression.variants_collapsed_to_total,
            if r.populations_emitted.is_empty() {
                "(none)".to_owned()
            } else {
                crate::output::join_untrusted(&r.populations_emitted)
            }
        )),
        Err(e) => crate::output::warn(&format!(
            "warning: could not compute the floor's impact ({e}); the floor is still applied"
        )),
    }
}

/// Quote `s` as a YAML double-quoted scalar with correct escaping.
///
/// Rust's `{:?}` is not a valid YAML escaper: it emits `\u{85}`-style sequences YAML
/// rejects, so a title or description carrying a control or non-printable character would
/// render an unparseable `package.yaml`. This emits the YAML double-quoted form: `\\`,
/// `\"`, `\n`, `\t`, `\r`, and `\xNN` for other C0/C1 control code points.
fn yaml_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            // Remaining C0 controls + DEL + C1 controls: YAML `\xNN`.
            c if (c as u32) < 0x20 || ('\u{7f}'..='\u{9f}').contains(&c) => {
                let _ = write!(out, "\\x{:02X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Render the collected values into a commented `package.yaml`. Pure + testable.
///
/// The rendered YAML can be round-tripped through `serde_saphyr::from_str::<PackageYaml>`
/// and `validate_package_collect_all` without errors (see the
/// `rendered_template_parses_and_validates` unit test, which acts as a drift guard).
///
/// # Panics
///
/// Never panics; all formatting is infallible.
#[must_use]
pub fn render_template(v: &AuthorValues) -> String {
    // Build optional blocks first so the main format! stays readable.
    let mut meta_opt = String::new();
    if !v.description.is_empty() {
        let _ = writeln!(meta_opt, "  description: {}", yaml_quote(&v.description));
    }
    if v.synthetic {
        let _ = writeln!(
            meta_opt,
            "  type: {}",
            yaml_quote(fields::SYNTHETIC_TYPE_IRI)
        );
    }
    if !v.keywords.is_empty() {
        meta_opt.push_str("  keywords:\n");
        for k in &v.keywords {
            let _ = writeln!(meta_opt, "    - {}", yaml_quote(k));
        }
    }
    if let Some(n) = v.number_of_unique_individuals {
        let _ = writeln!(meta_opt, "  numberOfUniqueIndividuals: {n}");
    }
    if !v.conforms_to_iris.is_empty() {
        meta_opt.push_str("  conformsTo:\n");
        for iri in &v.conforms_to_iris {
            let _ = writeln!(meta_opt, "    - {}", yaml_quote(iri));
        }
    }
    let mut cfg_opt = String::new();
    if let Some(s) = &v.af_source {
        let _ = writeln!(cfg_opt, "  afSource: {}", yaml_quote(s));
    }
    if let Some(s) = &v.af_source_reference {
        let _ = writeln!(cfg_opt, "  afSourceReference: {}", yaml_quote(s));
    }
    let mut files = String::new();
    for vcf in &v.vcf_paths {
        let _ = writeln!(files, "      - {}", yaml_quote(vcf));
    }
    let mut legislation = String::new();
    for iri in &v.applicable_legislation {
        let _ = writeln!(legislation, "    - {}", yaml_quote(iri));
    }
    let mut hc = String::new();
    for iri in &v.health_category_iris {
        let _ = writeln!(hc, "    - {}", yaml_quote(iri));
    }
    format!(
        "metadata:\n  \
prefix: {prefix}\n  org: {org}\n  catalog: {catalog}\n  title: {title}\n\
{meta_opt}  accessRights: {ar}\n  applicableLegislation:\n{legislation}  \
license: {lic}\n  creator:\n    - name: {creator}\n  healthCategory:\n{hc}\
\nfiles:\n  - category: \"VCF\"\n    reference: {asm}\n    files:\n{files}\
\ninternal: {{}}\n\nconfig:\n  mode: aggregated\n  blockRange: {br}\n  minAlleleCount: {mac}\n{cfg_opt}",
        prefix = yaml_quote(&v.prefix),
        org = yaml_quote(&v.org),
        catalog = yaml_quote(&v.catalog),
        title = yaml_quote(&v.title),
        ar = yaml_quote(&v.access_rights_iri),
        lic = yaml_quote(&v.license_iri),
        creator = yaml_quote(&v.creator),
        asm = yaml_quote(&v.assembly),
        br = v.block_range,
        mac = v.min_allele_count,
    )
}

/// Write `body` to `out`, refusing to overwrite without `force`, creating parents.
///
/// # Errors
///
/// Returns a [`ToolError`] if `out` already exists and `force` is false, or on any
/// filesystem error.
#[expect(
    clippy::disallowed_methods,
    reason = "writes a `package.yaml` draft for a human to review and edit"
)]
fn write_file(out: &Path, body: &str, force: bool) -> Result<(), ToolError> {
    if out.exists() && !force {
        return Err(ToolError::user(format!(
            "output already exists: {} (use --force to overwrite)",
            out.display()
        )));
    }
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        #[expect(
            clippy::disallowed_methods,
            reason = "operator-chosen path; the files inside carry their own mode"
        )]
        std::fs::create_dir_all(parent)
            .map_err(|e| ToolError::user(format!("cannot create {}: {e}", parent.display())))?;
    }
    std::fs::write(out, body)
        .map_err(|e| ToolError::user(format!("cannot write {}: {e}", out.display())))
}

/// Parse-back + holistic validation of a rendered package.yaml string.
///
/// # Errors
///
/// Returns a [`ToolError`] when the YAML does not parse or fails validation.
fn validate_rendered(yaml: &str) -> Result<(), ToolError> {
    let pkg: PackageYaml = serde_saphyr::from_str(yaml).map_err(|e| {
        ToolError::user(format!(
            "internal: rendered package.yaml did not parse: {e}"
        ))
    })?;
    let result = validate_package_collect_all(&pkg, None);
    if result.is_valid() {
        Ok(())
    } else {
        let problems = result
            .errors
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        Err(ToolError::user(format!(
            "the authored package.yaml has problems: {problems}"
        )))
    }
}

/// The distinct lines of `yaml` that still contain a `REPLACE:` placeholder.
#[must_use]
pub fn replace_markers(yaml: &str) -> Vec<String> {
    yaml.lines()
        .filter(|l| l.contains("REPLACE:"))
        .map(|l| l.trim().to_owned())
        .collect()
}

/// The validator for a `REPLACE:` marker, chosen by the YAML key it sits on.
///
/// Validating every marker as merely non-empty accepts a bad IRI or a bogus assembly at
/// its prompt and rejects it in a lump by [`validate_rendered`] after the last question --
/// at which point nothing is written and every answer is lost. Validating
/// at the prompt lets the operator correct the one field they got wrong.
///
/// Key-based only: guessing a type from the placeholder text would be a heuristic over
/// prose the operator may have edited. An unrecognised key keeps the non-empty rule, and
/// `validate_rendered` still backstops the whole document, so a missing entry here costs a
/// late error, never a bad package.
fn validator_for<'a>(key: &'a str, hint: &'a str) -> impl Fn(&str) -> Result<(), String> + 'a {
    move |s: &str| match key {
        "accessRights"
        | "license"
        | "afSourceReference"
        | "isReferencedBy"
        | "applicableLegislation" => fields::resolve_iri(key, s).map(|_| ()),
        "healthCategory" => fields::resolve_health_category(s).map(|_| ()),
        "reference" => fields::resolve_assembly(s).map(|_| ()),
        "hasEmail" => fields::resolve_email(s).map(|_| ()),
        _ => fields::resolve_nonempty(hint, s).map(|_| ()),
    }
}

/// The YAML key a `REPLACE:` line assigns to: its own, or — for a bare list scalar —
/// `parent`, the mapping key that opened the list.
///
/// Handles the three marker shapes the `init` template emits: `key: "REPLACE: ..."`,
/// `- name: "REPLACE: ..."` and the bare list scalar `- "REPLACE: ..."`.
///
/// The key is read from the text before the opening quote, not by splitting the line on
/// its first `:`: the marker text carries one too, so a bare list scalar would yield the
/// garbage key `"REPLACE`. That drops `healthCategory` and `applicableLegislation` to the
/// non-empty fallback, leaving their typed validators (a closed set, an IRI) unrun at the
/// prompt — the late lump-failure [`validator_for`] exists to prevent.
fn marker_key<'a>(line: &'a str, parent: &'a str) -> &'a str {
    let quote = line.find('"').unwrap_or(line.len());
    let head = line.get(..quote).unwrap_or(line);
    head.split_once(':').map_or(parent, |(lhs, _)| {
        lhs.trim().trim_start_matches("- ").trim()
    })
}

/// The mapping key a line opens a block for (`  healthCategory:`), if any — what
/// [`marker_key`] hands to the list scalars beneath it.
fn block_key(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let key = trimmed.strip_suffix(':')?;
    (!key.is_empty() && !key.starts_with(['-', '#'])).then_some(key)
}

/// Fix-up authoring: prompt a replacement for each remaining `REPLACE:` marker in
/// an existing `package.yaml`, review the result, and only on success back the prior
/// copy up to `<path>.bak` and rewrite the file in place.
///
/// The VCF marker is special: it takes one or many sources through the same prompt as
/// greenfield authoring (a directory of per-chromosome files is one answer), and every
/// path is resolved against the CWD it was typed in — an answer written verbatim would be
/// resolved against the YAML's directory at build time instead.
///
/// # Errors
///
/// Returns a [`ToolError`] if the file cannot be read/written, a prompt fails, or
/// the rewritten package fails validation.
pub fn author_fixup(p: &dyn Prompter, path: &Path) -> Result<AuthorResult, ToolError> {
    let original = std::fs::read_to_string(path)
        .map_err(|e| ToolError::user(format!("cannot read {}: {e}", path.display())))?;
    let mut lines: Vec<String> = Vec::new();
    let mut any = false;
    // The mapping key currently open, so a bare list scalar under it is validated as
    // what it is (`healthCategory`, `applicableLegislation`) rather than as free text.
    let mut parent_key = String::new();
    for line in original.lines() {
        if let Some(key) = block_key(line) {
            key.clone_into(&mut parent_key);
        }
        if !line.contains("REPLACE:") {
            lines.push(line.to_owned());
            continue;
        }
        any = true;
        // Extract the hint text between "REPLACE:" and the closing quote for the
        // prompt. This works for all three marker shapes in the init template:
        //   key: "REPLACE: ..."        (simple key-value)
        //   - name: "REPLACE: ..."     (list-item with a named key)
        //   - "REPLACE: ..."           (bare list scalar)
        let hint = line
            .split_once("REPLACE:")
            .map_or("value", |(_, rest)| rest.trim_end_matches('"').trim())
            .to_owned();
        // Replace from the first '"' (the opening quote of the REPLACE scalar) to
        // the end of the line, preserving the entire prefix before that quote.
        // This keeps "  key: ", "    - name: ", and "    - " prefixes intact.
        let prefix_end = line.find('"').unwrap_or(line.len());
        let (prefix, _) = line.split_at(prefix_end);
        if hint.to_ascii_lowercase().contains(".vcf") {
            let sources = collect_vcf_sources(p)?;
            for vcf in sources.paths {
                lines.push(format!("{prefix}{}", yaml_quote(&vcf)));
            }
            continue;
        }
        let key = marker_key(line, &parent_key).to_owned();
        let validate = validator_for(&key, &hint);
        let answer = p.input_validated(&format!("Fill in ({hint})"), None, &validate)?;
        // Quote the answer with `yaml_quote`, not Rust's `{:?}`, which emits `\u{XX}`-style
        // escapes YAML rejects. This matches the greenfield `render_template` path, so a
        // non-printable answer still produces valid YAML.
        lines.push(format!("{prefix}{}", yaml_quote(&answer)));
    }
    if !any {
        crate::output::progress("no REPLACE: markers found; package.yaml left unchanged");
        return Ok(AuthorResult {
            path: path.to_path_buf(),
            org_to_store: None,
        });
    }
    let rewritten = format!("{}\n", lines.join("\n"));
    validate_rendered(&rewritten)?;
    let rewritten = review_before_write(p, rewritten)?;
    write_with_backup(path, &rewritten)?;
    crate::output::progress(&format!("updated package.yaml at {}", path.display()));
    Ok(AuthorResult {
        path: path.to_path_buf(),
        org_to_store: None,
    })
}

/// Back the prior file up to `<path>.bak`, then rewrite `path` in place.
///
/// # Errors
///
/// Returns a [`ToolError`] on either filesystem failure.
#[expect(
    clippy::disallowed_methods,
    reason = "an in-place rewrite of a user-owned file, preceded by a `.bak` copy on the line above"
)]
fn write_with_backup(path: &Path, contents: &str) -> Result<(), ToolError> {
    let mut bak = path.as_os_str().to_owned();
    bak.push(".bak");
    #[expect(
        clippy::disallowed_methods,
        reason = "package.yaml carries dataset configuration, not credentials, so carrying \
                  the source mode to its sibling backup preserves the operator's choice"
    )]
    std::fs::copy(path, &bak)
        .map_err(|e| ToolError::user(format!("cannot back up {}: {e}", path.display())))?;
    std::fs::write(path, contents)
        .map_err(|e| ToolError::user(format!("cannot write {}: {e}", path.display())))
}

/// Ask for `numberOfUniqueIndividuals`, treating a blank answer as "not recorded".
///
/// The prompt offers no default, and a blank answer yields `None`, matching the
/// `afSourceReference` prompt below. An active `numberOfUniqueIndividuals: 0` is a valid
/// cohort size, so it passes `--strict` silently, whereas an absent field makes the
/// recommended-field-absent path warn and nudge the provider. Pre-filling `0` would let two
/// Enter presses publish a dataset advertising zero sequenced subjects.
///
/// # Errors
///
/// Propagates a prompt failure.
fn prompt_cohort_size(p: &dyn Prompter) -> Result<Option<u64>, ToolError> {
    // "recommended; build warns" makes declining an informed decline: the wizard used
    // to offer the skip and the build then immediately printed `recommended field
    // "numberOfUniqueIndividuals" is absent`, looking like a mistake.
    crate::output::progress(
        "  numberOfUniqueIndividuals: recommended; build warns when it is absent.",
    );
    if !p.confirm("Record cohort size?", true)? {
        return Ok(None);
    }
    let raw = p.input_validated(
        "Distinct sequenced subjects (blank to skip)",
        None,
        &|s: &str| {
            if s.trim().is_empty() {
                return Ok(());
            }
            fields::resolve_u64("numberOfUniqueIndividuals", s).map(|_| ())
        },
    )?;
    Ok(raw.trim().parse::<u64>().ok())
}

/// A group header inside the Author flow — always-on so `-q` cannot orphan the prompts
/// from the context that names where their answers surface.
fn section(title: &str) {
    crate::output::section_caption(title);
}

/// Whether the legislation step opens with the GDPR row pre-ticked. Yes exactly when
/// shipped headers would carry personal data — a `with-identifiers` profile over sources
/// that have sample columns.
fn gdpr_default(
    header_policy: Option<gdi_node_standalone_core::config::ProfileHeaderPolicy>,
    samples_total: usize,
) -> bool {
    use gdi_node_standalone_core::config::ProfileHeaderPolicy;
    matches!(header_policy, Some(ProfileHeaderPolicy::WithIdentifiers)) && samples_total > 0
}

/// Parse a comma-separated keyword answer: trimmed, empties dropped, and exact duplicates
/// removed keeping first-seen order, so a repeated keyword is written once.
fn parse_keywords(raw: &str) -> Vec<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| seen.insert((*s).to_owned()))
        .map(str::to_owned)
        .collect()
}

/// Prompt-time validation for the keyword list, reusing core's own caps so an over-long
/// answer is re-asked here instead of failing the review loop.
fn validate_keywords(s: &str) -> Result<(), String> {
    use gdi_node_standalone_core::validate_pkg::{MAX_KEYWORD_LEN, MAX_KEYWORDS_COUNT};
    let parsed = parse_keywords(s);
    if parsed.len() > MAX_KEYWORDS_COUNT {
        return Err(format!("at most {MAX_KEYWORDS_COUNT} keywords"));
    }
    if let Some(too_long) = parsed.iter().find(|k| k.chars().count() > MAX_KEYWORD_LEN) {
        return Err(format!(
            "keyword {too_long:?} exceeds the {MAX_KEYWORD_LEN}-char limit"
        ));
    }
    Ok(())
}

/// Resolve the operator's VCF answer to an absolute path, once, at the point of entry.
///
/// The wizard reads the VCF through the process CWD (preview, floor-impact sampling) but
/// writes the answer into `package.yaml`, where `build` resolves relative paths against the
/// YAML's own directory. Whenever the wizard runs outside the package directory those are
/// two different files: the preview reports on one and the build reads the other, or
/// fails outright. Canonicalizing here makes every later reader agree.
///
/// An answer that does not resolve is returned untouched so the preview reports the
/// operator's own spelling instead of a canonicalization error about it.
fn resolve_vcf_input(input: &str) -> String {
    std::fs::canonicalize(input).map_or_else(
        |_| input.to_owned(),
        |abs| abs.to_string_lossy().into_owned(),
    )
}

/// What the wizard knows from the active profile when authoring a fresh `package.yaml`.
#[derive(Default)]
pub struct AuthorContext<'a> {
    /// The profile's catalog allow-list (name → display title); empty when nothing is
    /// pinned.
    pub catalogs: BTreeMap<String, String>,
    /// The profile's `org`. When set the wizard prints it and never asks: the dataset id's
    /// organisation segment is the provider's identity (an integrating backend refuses an
    /// id carrying any other), not a per-dataset choice.
    pub org: Option<&'a str>,
    /// Fetch the node's catalogs and persist them into the profile — what `catalogs --sync`
    /// does — returning the new allow-list. `None` when the profile has no `service_url`.
    pub refresh_catalogs: Option<&'a dyn Fn() -> Result<BTreeMap<String, String>, ToolError>>,
    /// The profile's `header_policy`, when it has one — under `with-identifiers` a
    /// source that carries sample columns ships personal data, which pre-ticks the GDPR
    /// row of the legislation step.
    pub header_policy: Option<gdi_node_standalone_core::config::ProfileHeaderPolicy>,
}

/// The file names the converter's reader accepts (`preflight_vcf_format`'s extension rule,
/// case-insensitive).
const VCF_EXTENSIONS: [&str; 4] = [".vcf", ".vcf.gz", ".vcf.bgz", ".vcf.bgzf"];

/// Whether `name` carries one of [`VCF_EXTENSIONS`].
fn is_vcf_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    VCF_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// The file name of `path`, lossily, for prompts and progress lines.
fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The VCFs directly inside `dir`, in natural (`chr1`, `chr2`, … `chr10`) order.
///
/// # Errors
///
/// Returns a [`ToolError`] when the directory cannot be read.
fn list_vcfs(dir: &Path) -> Result<Vec<PathBuf>, ToolError> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| ToolError::user(format!("cannot read {}: {e}", dir.display())))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && is_vcf_name(&file_name_of(path)))
        .collect();
    found.sort_by(|a, b| natural_cmp(&file_name_of(a), &file_name_of(b)));
    Ok(found)
}

/// Split `s` into maximal runs of digits and non-digits, for [`natural_cmp`].
fn natural_chunks(s: &str) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut in_digits: Option<bool> = None;
    for (i, c) in s.char_indices() {
        let digit = c.is_ascii_digit();
        if let Some(previous) = in_digits
            && previous != digit
        {
            chunks.push(s.get(start..i).unwrap_or_default());
            start = i;
        }
        in_digits = Some(digit);
    }
    if start < s.len() {
        chunks.push(s.get(start..).unwrap_or_default());
    }
    chunks
}

/// Compare two names the way a person reads them: digit runs by value, so `chr2` sorts
/// before `chr10` (a byte sort puts `chr10` between `chr1` and `chr2`, which is the order a
/// per-chromosome directory would otherwise be listed and declared in).
///
/// Shared with the path prompt's Tab completion ([`crate::wizard::prompts`]): the
/// directory multi-select and the completion candidates list the same files, and two
/// orderings for one set of names is exactly the drift this crate deletes rather than
/// guards.
pub(crate) fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let is_number = |chunk: &str| !chunk.is_empty() && chunk.bytes().all(|b| b.is_ascii_digit());
    let (chunks_a, chunks_b) = (natural_chunks(a), natural_chunks(b));
    for (x, y) in chunks_a.iter().zip(chunks_b.iter()) {
        let ordering = if is_number(x) && is_number(y) {
            let (xs, ys) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
            xs.len().cmp(&ys.len()).then_with(|| xs.cmp(ys))
        } else {
            x.cmp(y)
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    chunks_a.len().cmp(&chunks_b.len())
}

/// The path-prompt validator: an existing file, or a directory holding at least one VCF.
fn validate_vcf_source(s: &str) -> Result<(), String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("a path is required".to_owned());
    }
    let path = Path::new(t);
    if path.is_dir() {
        return match list_vcfs(path) {
            Ok(found) if !found.is_empty() => Ok(()),
            Ok(_) => Err(format!(
                "{t} holds no VCF (.vcf / .vcf.gz) files; name a file or another directory"
            )),
            Err(e) => Err(e.message),
        };
    }
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("{t} does not exist (Tab completes paths)"))
    }
}

/// Everything the wizard learned from the source VCFs at the prompt.
#[derive(Debug)]
struct SourceSummary {
    /// Absolute paths, in the order the operator gave them (a directory expands to its
    /// VCFs in natural order).
    paths: Vec<String>,
    /// The headers' assembly, when every source that names one agrees.
    assembly_hint: Option<&'static str>,
    /// How many sources named an assembly at all — so the hint message can say
    /// "read from 2 of 3 VCF headers" instead of implying one file was consulted.
    assembly_named: usize,
    /// Sample columns across all sources — under a `with-identifiers` profile a
    /// non-zero count means shipped headers carry personal data (GDPR default flips).
    samples_total: usize,
}

/// Ask for the source VCFs and preview their headers, until a readable set is named.
///
/// A source the reader cannot open is not a "continue anyway?" — the preview runs the
/// converter's own header validation, so a file that fails here fails `build` the same way.
/// The only useful answers are to name the files again or to stop.
fn collect_vcf_sources(p: &dyn Prompter) -> Result<SourceSummary, ToolError> {
    loop {
        let paths = prompt_vcf_paths(p)?;
        match preview_sources(&paths) {
            Ok((assembly_hint, assembly_named, samples_total)) => {
                return Ok(SourceSummary {
                    paths,
                    assembly_hint,
                    assembly_named,
                    samples_total,
                });
            }
            Err(e) => {
                crate::output::warn(&format!("warning: {}", e.message));
                let choice = p.select(
                    "A source VCF could not be read. What next?",
                    &["Enter the path(s) again".into(), "Abort".into()],
                    0,
                )?;
                if choice != 0 {
                    return Err(ToolError::user(
                        "aborted: a source VCF could not be read; fix or replace the file, \
                         then re-run the wizard",
                    ));
                }
            }
        }
    }
}

/// The path with one trailing compression suffix (`.gz`/`.bgz`/`.bgzf`) removed — the
/// identity under which `x.vcf` and `x.vcf.gz` are the same source twice.
fn compression_base(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    for ext in [".gz", ".bgz", ".bgzf"] {
        if lower.ends_with(ext) {
            // The suffix is ASCII and `to_ascii_lowercase` preserves byte offsets, so
            // the cut is on a char boundary; `get` keeps the no-panic guarantee anyway.
            return path
                .get(..path.len() - ext.len())
                .unwrap_or(path)
                .to_owned();
        }
    }
    path.to_owned()
}

/// Warn when two selected sources are the same path apart from compression
/// (`x.vcf` beside `x.vcf.gz`): the same variants twice fail the build's dataset-wide
/// `(POS, REF, ALT, population)` uniqueness scan — but only after every conversion,
/// minutes into a whole-chromosome set, with an error that cannot name the files. The
/// The same name in different directories is not flagged: a per-population split
/// legitimately repeats file names across directories.
fn warn_same_data_twins(paths: &[String]) {
    let mut by_base: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in paths {
        by_base
            .entry(compression_base(path))
            .or_default()
            .push(path.clone());
    }
    for twins in by_base.values().filter(|twins| twins.len() > 1) {
        crate::output::warn(&format!(
            "warning: {} look like the SAME data (one name, different compression); \
             building both fails on duplicate variants; drop one unless they really differ",
            crate::output::join_untrusted(twins)
        ));
    }
}

/// One or more VCF paths from the operator: a file each, or a directory whose VCFs are
/// offered as a pre-checked multi-select, repeated while they want to add more. Every path
/// is resolved against the CWD it was typed in (see [`resolve_vcf_input`]) and deduplicated.
fn prompt_vcf_paths(p: &dyn Prompter) -> Result<Vec<String>, ToolError> {
    // Said once, above the prompt rather than inside it: a prompt wider than the terminal
    // wraps, and dialoguer clears only the last row when it finalizes, so the question is
    // left on screen above its own answer.
    crate::output::progress("  plain .vcf or .vcf.gz; a directory offers its VCFs to pick from.");
    let mut paths: Vec<String> = Vec::new();
    loop {
        let answer = p.input_path(
            "VCF file or directory of VCFs (Tab completes)",
            None,
            &validate_vcf_source,
        )?;
        let source = resolve_vcf_input(answer.trim());
        let source_path = Path::new(&source);
        if source_path.is_dir() {
            let found = list_vcfs(source_path)?;
            let labels: Vec<String> = found.iter().map(|f| file_name_of(f)).collect();
            let checked = vec![true; labels.len()];
            let chosen = p.multiselect(
                &format!(
                    "VCFs in {} to include (Space toggles, Enter confirms)",
                    crate::output::Untrusted(&source)
                ),
                &labels,
                &checked,
            )?;
            if chosen.is_empty() {
                crate::output::warn(&format!(
                    "warning: no file selected from {}",
                    crate::output::Untrusted(&source)
                ));
            }
            for i in chosen {
                if let Some(f) = found.get(i) {
                    paths.push(f.to_string_lossy().into_owned());
                }
            }
        } else {
            paths.push(source);
        }
        let mut seen: BTreeSet<String> = BTreeSet::new();
        paths.retain(|path| seen.insert(path.clone()));
        if p.confirm("Add another VCF file or directory?", false)? {
            continue;
        }
        if paths.is_empty() {
            crate::output::warn("warning: no VCF selected yet");
            continue;
        }
        warn_same_data_twins(&paths);
        return Ok(paths);
    }
}

/// Header-only preview of every source: the populations each one publishes, their union,
/// a same-contig note, and the assembly hint. Reads no records — the disclosure gate at
/// Build shows the population list again, and `build` scans every file once.
///
/// Returns `(assembly_hint, assembly_named, samples_total)`: the consensus assembly
/// (when every source that names one agrees), how many sources named one at all, and
/// the sample columns summed across every source.
///
/// # Errors
///
/// Returns a [`ToolError`] naming the first source whose header cannot be read or fails the
/// converter's header validation.
fn preview_sources(paths: &[String]) -> Result<(Option<&'static str>, usize, usize), ToolError> {
    let total = paths.len();
    let unreadable = |vcf: &Path, e: &gdi_node_standalone_core::error::CoreError| {
        let e = ToolError::from_vcf_stage(e);
        ToolError::user(format!("preview of {}: {}", vcf.display(), e.message))
    };
    let mut union: BTreeSet<String> = BTreeSet::new();
    let mut assemblies: Vec<&'static str> = Vec::new();
    let mut samples_total: usize = 0;
    let mut starts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    crate::output::progress(&format!(
        "preview: populations in the {total} source VCF(s), from the headers:"
    ));
    for (i, path) in paths.iter().enumerate() {
        let vcf = Path::new(path);
        let pops = read_header_populations(vcf).map_err(|e| unreadable(vcf, &e))?;
        let hints = read_header_hints(vcf).map_err(|e| unreadable(vcf, &e))?;
        let name = file_name_of(vcf);
        crate::output::progress(&format!(
            "  [{}/{total}] {}: {}",
            i + 1,
            crate::output::Untrusted(&name),
            if pops.is_empty() {
                "(no population carries an AF field; this source emits no rows)".to_owned()
            } else {
                crate::output::join_untrusted(&pops)
            }
        ));
        union.extend(pops);
        if let Some(assembly) = hints.assembly {
            assemblies.push(assembly);
        }
        samples_total += hints.samples;
        if let Some(contig) = hints.first_contig {
            starts.entry(contig).or_default().push(name);
        }
    }
    if total > 1 {
        let all: Vec<String> = union.iter().cloned().collect();
        crate::output::progress(&format!(
            "  union across all {total} sources ({}): {}",
            all.len(),
            crate::output::join_untrusted(&all)
        ));
        for (contig, names) in starts.iter().filter(|(_, names)| names.len() > 1) {
            crate::output::progress(&format!(
                "  note: {} all start on contig {}; if they are per-population files over \
                 the SAME loci the node must buffer each block to serve them (one VCF per \
                 position range keeps it streaming; see the `files` section of \
                 docs/gdi-dataset-tool.md)",
                crate::output::join_untrusted(names),
                crate::output::Untrusted(contig)
            ));
        }
    }
    if union.is_empty() {
        crate::output::warn(
            "warning: no source carries an AF field, so the build would produce an empty \
             dataset and fail",
        );
    }
    let assembly_hint = match assemblies.as_slice() {
        [] => None,
        [first, rest @ ..] if rest.iter().all(|a| a == first) => Some(*first),
        _ => {
            crate::output::warn(
                "warning: the source headers name different assemblies; check that every \
                 file was called against the same build",
            );
            None
        }
    };
    Ok((assembly_hint, assemblies.len(), samples_total))
}

/// The catalog list's last row: fetch the node's current catalogs and re-ask.
const REFRESH_CATALOGS_LABEL: &str = "Refresh the list from the node...";

/// A catalog's row in the list: the name, with its display title when one is configured.
fn catalog_label(name: &str, title: &str) -> String {
    if title.is_empty() || title == name {
        name.to_owned()
    } else {
        format!("{name}: {title}")
    }
}

/// Run a catalog refresh and report on it; `None` when it failed or the node lists nothing,
/// so the caller keeps whatever list it had.
fn refreshed_catalogs(
    refresh: &dyn Fn() -> Result<BTreeMap<String, String>, ToolError>,
) -> Option<BTreeMap<String, String>> {
    match refresh() {
        Ok(fetched) if !fetched.is_empty() => Some(fetched),
        Ok(_) => {
            crate::output::warn("warning: the node reports no catalogs; keeping the current list");
            None
        }
        Err(e) => {
            crate::output::warn(&format!(
                "warning: catalog refresh failed ({}); keeping the current list",
                e.message
            ));
            None
        }
    }
}

/// Pick `metadata.catalog`.
///
/// From the profile's pinned allow-list when it has one — plus a "refresh from the node"
/// row, because the list is synced at setup and a catalog the node gained since is
/// otherwise unreachable (and `build` rejects a name outside a non-empty list). There is
/// no "type another name" row while a list exists: that name would fail the build for the
/// same reason. With nothing pinned, the refresh is offered first and free text is the
/// fallback.
fn prompt_catalog(p: &dyn Prompter, ctx: &AuthorContext<'_>) -> Result<String, ToolError> {
    let mut catalogs = ctx.catalogs.clone();
    loop {
        if catalogs.is_empty() {
            if let Some(refresh) = ctx.refresh_catalogs
                && {
                    crate::output::progress("  no catalogs are pinned in the profile.");
                    p.confirm("Fetch the node's catalog list now?", true)?
                }
                && let Some(fetched) = refreshed_catalogs(refresh)
            {
                catalogs = fetched;
                continue;
            }
            // Take the resolver's output, not the raw entry: `resolve_nonempty` trims and
            // every other free-text field is stored as it resolves. Returning the raw
            // answer here made `catalog` the one field that kept surrounding whitespace —
            // and it is the field that must match the node's allow-list exactly, so
            // "  gdi-aggregated  " passed `build`, reached the shipped manifest, and could
            // only fail at the node, with the spaces invisible in every echo along the way.
            let answer = p.input_validated(
                "Catalog name (as the node's [catalogs] config spells it)",
                None,
                &|s| fields::resolve_nonempty("catalog", s).map(|_| ()),
            )?;
            return Ok(fields::resolve_nonempty("catalog", &answer).unwrap_or(answer));
        }
        let names: Vec<&String> = catalogs.keys().collect();
        let mut labels: Vec<String> = catalogs
            .iter()
            .map(|(name, title)| catalog_label(name, title))
            .collect();
        if ctx.refresh_catalogs.is_some() {
            labels.push(REFRESH_CATALOGS_LABEL.to_owned());
        }
        let idx = p.select("Catalog", &labels, 0)?;
        match names.get(idx) {
            Some(name) => return Ok((*name).clone()),
            None => {
                if let Some(refresh) = ctx.refresh_catalogs
                    && let Some(fetched) = refreshed_catalogs(refresh)
                {
                    catalogs = fetched;
                }
            }
        }
    }
}

/// The review menu, in order. `Write` is the default: the document was just validated.
const REVIEW_CHOICES: [&str; 3] = [
    "Write it",
    "Edit it in $EDITOR first",
    "Abort (the answers are discarded)",
];

/// Print a document to stderr line by line, each line sanitised for the terminal.
fn print_document(text: &str) {
    crate::output::yaml_block(text);
}

/// The last look before anything is written: the rendered `package.yaml`, then the choice
/// to write it, edit it in the editor first, or abort.
///
/// The prompts validate answers, not decisions — a typo in the title or the wrong
/// catalog passes every validator — and until here the only remedies were Ctrl-C (every
/// answer gone) or a hand edit after the fact. "Edit" re-validates in a loop, so what is
/// finally written is always a package the build accepts.
///
/// # Errors
///
/// Returns a [`ToolError`] on a prompt failure, or when the operator aborts.
fn review_before_write(p: &dyn Prompter, mut yaml: String) -> Result<String, ToolError> {
    loop {
        // Its own section. This is the review, not part of Disclosure controls above it,
        // and running the two together left a ~30-line document reading as more wizard
        // output with nothing marking where it began or ended.
        section("Review: package.yaml as it will be written");
        print_document(&yaml);
        match p.select("Write package.yaml?", &REVIEW_CHOICES.map(String::from), 0)? {
            0 => match validate_rendered(&yaml) {
                Ok(()) => return Ok(yaml),
                Err(e) => {
                    crate::output::warn(&format!("warning: {}; edit it or abort", e.message));
                }
            },
            1 => {
                yaml = p.editor("Edit package.yaml, then save and close the editor", &yaml)?;
                if let Err(e) = validate_rendered(&yaml) {
                    crate::output::warn(&format!("warning: {}; edit it again or abort", e.message));
                }
            }
            _ => {
                return Err(ToolError::user(
                    "aborted before writing package.yaml: the answers were discarded; \
                     re-run the wizard to start over",
                ));
            }
        }
    }
}

/// Open a complete `package.yaml` in the editor before building — the marker-free
/// counterpart of [`author_fixup`]: the edit is validated and reviewed, then written back
/// with a `.bak` of the prior file.
///
/// # Errors
///
/// Returns a [`ToolError`] if the file cannot be read/written, a prompt fails, or the
/// operator aborts the review.
pub fn edit_existing(p: &dyn Prompter, path: &Path) -> Result<(), ToolError> {
    let current = std::fs::read_to_string(path)
        .map_err(|e| ToolError::user(format!("cannot read {}: {e}", path.display())))?;
    let edited = p.editor(
        "Edit package.yaml, then save and close the editor",
        &current,
    )?;
    if edited == current {
        crate::output::progress("package.yaml left unchanged");
        return Ok(());
    }
    let reviewed = review_before_write(p, edited)?;
    write_with_backup(path, &reviewed)?;
    crate::output::progress(&format!("updated package.yaml at {}", path.display()));
    Ok(())
}

/// Greenfield authoring: prompt the fields, preview the VCF headers, review, write.
///
/// # Errors
///
/// Returns a [`ToolError`] on a failed prompt, an unusable VCF (preview), a write
/// failure, or a rendered package that fails validation.
#[expect(
    clippy::too_many_lines,
    reason = "the prompts are sequential; splitting further would lose readability"
)]
pub fn author_greenfield(
    p: &dyn Prompter,
    out: &Path,
    ctx: &AuthorContext<'_>,
    force: bool,
) -> Result<AuthorResult, ToolError> {
    // 1. Sources first, then their header preview (fail fast on an unreadable VCF).
    section("Source data");
    let sources = collect_vcf_sources(p)?;
    // Pre-select what the header says; never skip the question — a lifted-over VCF can
    // carry its source header.
    let assembly_default = sources
        .assembly_hint
        .and_then(|hint| fields::ASSEMBLIES.iter().position(|a| *a == hint))
        .unwrap_or(1);
    if let Some(hint) = sources.assembly_hint {
        // Every header was read; the hint pre-selects only when all that name an
        // assembly agree — say how many did, so "the VCF header" never reads as
        // "one file was consulted" on a multi-source set.
        let total = sources.paths.len();
        if total > 1 {
            crate::output::progress(&format!(
                "assembly {hint} read from {} of {total} VCF headers; confirm it, or \
                 pick the other",
                sources.assembly_named
            ));
        } else {
            crate::output::progress(&format!(
                "assembly {hint} read from the VCF header; confirm it, or pick the other"
            ));
        }
    }
    let asm_idx = p.select(
        "Assembly",
        fields::ASSEMBLIES.map(String::from).as_ref(),
        assembly_default,
    )?;
    let assembly = fields::ASSEMBLIES[asm_idx].to_owned();

    // 2. The catalog entry — everything the node's FAIR Data Point publishes about
    //    the dataset, grouped so the provider knows where these answers surface.
    section("Catalog entry: published via the node's FAIR Data Point");
    let prefix_idx = p.select(
        "Dataset ID prefix",
        fields::PREFIXES.map(String::from).as_ref(),
        0,
    )?;
    let prefix = fields::PREFIXES[prefix_idx].to_owned();
    // The org is the provider's identity, half of every dataset id: from the profile when
    // it is known there, else asked once and offered to the profile so it is never asked
    // again.
    let (org, org_to_store) = if let Some(profile_org) = ctx.org {
        crate::output::progress(&format!("org: {profile_org} (from the profile)"));
        (profile_org.to_owned(), None)
    } else {
        let org_raw = p.input_validated("Institute abbreviation (e.g. UTARTU)", None, &|s| {
            fields::resolve_org(s).map(|_| ())
        })?;
        // Normalize to the up-cased form the dataset-id build requires (validated above).
        let org = fields::resolve_org(&org_raw).unwrap_or(org_raw);
        let store = p.confirm(
            &format!("Remember {org} in the profile, so future datasets never ask?"),
            true,
        )?;
        (org.clone(), store.then_some(org))
    };
    let catalog = prompt_catalog(p, ctx)?;
    let title = p.input_validated("Dataset title", None, &|s| {
        fields::resolve_bounded("title", s, MAX_TITLE_LEN).map(|_| ())
    })?;
    let description = p.input_validated("Description", None, &|s| {
        fields::resolve_bounded("description", s, MAX_DESCRIPTION_LEN).map(|_| ())
    })?;
    let keywords = if p.confirm("Add discovery keywords?", true)? {
        let raw = p.input_validated(
            "Keywords (comma-separated)",
            Some("allele-frequency,genomics"),
            &|s| validate_keywords(s),
        )?;
        parse_keywords(&raw)
    } else {
        Vec::new()
    };
    let number_of_unique_individuals = prompt_cohort_size(p)?;
    let synthetic = p.confirm("Is this synthetic data?", false)?;
    // Role contrast, no example value: setup asks for an "Institute abbreviation
    // (e.g. UTARTU)" and this looks like the same question, but it is the human-readable
    // `dct:creator` the catalog shows.
    crate::output::progress(
        "  the full public name shown in the catalog entry: not the ID abbreviation from \
         setup.",
    );
    let creator = p.input_validated("Creating organisation", None, &|s| {
        fields::resolve_bounded("creator", s, MAX_CREATOR_NAME_LEN).map(|_| ())
    })?;
    let health_category_iris = prompt_health_categories(p)?;
    // Also catalog metadata: `dct:conformsTo` is a claim about the dataset the FDP
    // publishes beside its health categories, not about reuse terms.
    let conforms_to_iris = prompt_conforms_to(p)?;

    // 3. Access & legal — also part of the catalog entry, grouped apart because these
    //    are claims about reuse rather than description.
    section("Access & legal");
    // Pre-select RESTRICTED (index 1), not PUBLIC (index 0). dialoguer returns the default on
    // a bare Enter, so tabbing through the wizard published the most permissive value on
    // offer. The NON-interactive twin does the opposite: `cmd_init`'s template makes this a
    // `REPLACE:` marker annotated "Always explicit", and build/validate refuse a package with
    // a leftover marker — so the headless path forced a decision that the interactive path,
    // used by more operators, defaulted away. The node audits a RESTRICTED -> PUBLIC move as
    // an administrator-attributed broadening, which is the shape of thing that should be
    // chosen rather than inherited.
    let ar_idx = p.select("Access rights", &fields::access_right_labels(), 1)?;
    let access_rights_iri = fields::access_right_iri(ar_idx).to_owned();
    let license_iri = prompt_curated_iri(
        p,
        "License",
        "License IRI",
        "license",
        fields::LICENSE_SUGGESTIONS,
    )?;

    // `applicableLegislation` is required (1..n). One step covers all of it: the EHDS and
    // GDPR rows, then free entry. The GDPR row is pre-checked when the dataset discloses
    // personal data, which it does under a with-identifiers profile whose sources carry
    // sample columns.
    let applicable_legislation =
        prompt_applicable_legislation(p, ctx.header_policy, sources.samples_total)?;

    // 4. Beacon provenance: `config.afSource`/`afSourceReference` label every Beacon
    //    answer's `frequencyInPopulations` source/sourceReference (GA4GH-required
    //    fields) — not catalog metadata, hence their own group.
    section("Beacon provenance: cited in every Beacon answer");
    // Offered as a CONFIRM rather than an `input` default: a dialoguer default makes a
    // blank submit impossible, which would silently remove the "leave both unset" path.
    // Accepting sets both fields — the pair is one provenance claim, and taking the
    // source while skipping its reference would author a claim with no anchor.
    crate::output::progress("  sets both afSource and afSourceReference.");
    let (af_source, af_source_reference) =
        if p.confirm("Use the standard Genome of Europe AF provenance?", true)? {
            (
                Some(fields::GOE_AF_SOURCE.to_owned()),
                Some(fields::GOE_AF_SOURCE_REFERENCE.to_owned()),
            )
        } else {
            let af_source = optional_text(p, "Allele-frequency source (afSource)")?;
            // Reprompt-validate the optional afSource reference URL: a blank answer skips it,
            // and a typo re-prompts instead of aborting the whole wizard and discarding every
            // prior answer.
            let af_source_reference = {
                let answer =
                    p.input_validated("afSource reference URL (blank to skip)", None, &|s| {
                        if s.trim().is_empty() {
                            Ok(())
                        } else {
                            fields::resolve_iri("afSourceReference", s).map(|_| ())
                        }
                    })?;
                let t = answer.trim();
                (!t.is_empty()).then(|| t.to_owned())
            };
            (af_source, af_source_reference)
        };

    // 5. Asked last, so it is the final input in the flow. Then show what it costs on
    // this VCF: providers otherwise pick a number blind, and the counters make the
    // trade concrete before the package.yaml is written.
    section("Disclosure controls");
    let min_allele_count = prompt_min_allele_count(p)?;
    if let Some(first) = sources.paths.first() {
        report_floor_impact(
            Path::new(first),
            &assembly,
            min_allele_count,
            sources.paths.len(),
        );
    }

    let values = AuthorValues {
        prefix,
        org,
        catalog,
        title,
        description,
        access_rights_iri,
        license_iri,
        creator,
        health_category_iris,
        conforms_to_iris,
        applicable_legislation,
        keywords,
        number_of_unique_individuals,
        af_source,
        af_source_reference,
        vcf_paths: sources.paths,
        assembly,
        block_range: 10_000_000,
        min_allele_count,
        synthetic,
    };
    let yaml = render_template(&values);
    validate_rendered(&yaml)?;
    let yaml = review_before_write(p, yaml)?;
    write_file(out, &yaml, force)?;
    crate::output::progress(&format!("wrote {}", out.display()));
    Ok(AuthorResult {
        path: out.to_path_buf(),
        org_to_store,
    })
}

/// Pick ≥1 health categories from the vendored closed set — a multi-select with
/// "Human genomic" pre-checked, labels derived from the IRIs (`fields::health_category_choices`).
///
/// `healthCategory` is 1..n and closed: the node rejects any IRI outside the vendored
/// `DatasetShape` set, so there is no free-text escape, which could only author a package
/// the build refuses, and an empty selection re-asks. A re-vendored, wider set appears here
/// automatically.
///
/// # Errors
///
/// Returns a [`ToolError`] on a prompt failure.
fn prompt_health_categories(p: &dyn Prompter) -> Result<Vec<String>, ToolError> {
    let choices = fields::health_category_choices();
    let labels: Vec<String> = choices.iter().map(|(label, _)| label.clone()).collect();
    let checked: Vec<bool> = choices
        .iter()
        .map(|(_, iri)| fields::iri_tail(iri) == "HealthCategoryHumanGenomic")
        .collect();
    loop {
        let chosen = p.multiselect(
            "Health categories (EHDS Art. 51; Space toggles, Enter confirms)",
            &labels,
            &checked,
        )?;
        if !chosen.is_empty() {
            return Ok(chosen
                .iter()
                .filter_map(|&i| choices.get(i))
                .map(|(_, iri)| (*iri).to_owned())
                .collect());
        }
        crate::output::warn("warning: at least one health category is required");
    }
}

/// Pick 0..n GDI standards from the vendored `conformsTo` closed set: a multi-select with
/// nothing pre-checked, where an empty selection omits `metadata.conformsTo` entirely.
///
/// Nothing is pre-checked because a blanket default would invent a per-dataset fact. The set
/// is closed, so the node rejects any IRI outside it and there is no free-text escape. The
/// labels come from the shape's own `rdfs:label`.
///
/// # Errors
///
/// Returns a [`ToolError`] on a prompt failure.
fn prompt_conforms_to(p: &dyn Prompter) -> Result<Vec<String>, ToolError> {
    let choices = fields::conforms_to_choices();
    let labels: Vec<String> = choices.iter().map(|(label, _)| label.clone()).collect();
    // Said above the prompt, not inside it: the prompt has an 80-column budget, and
    // "nothing ticked" is otherwise an invisible, valid answer.
    crate::output::progress(
        "  optional: a compliance claim about THIS dataset; leave everything unticked \
         to omit it.",
    );
    let chosen = p.multiselect(
        "Conforms to (GDI standards); Space toggles, Enter confirms",
        &labels,
        &vec![false; labels.len()],
    )?;
    Ok(chosen
        .iter()
        .filter_map(|&i| choices.get(i))
        .map(|(_, iri)| (*iri).to_owned())
        .collect())
}

/// The `applicableLegislation` multi-select rows: `(label, IRI, pre-checked)`.
///
/// The EHDS row is always pre-checked, because it is the shape's `sh:defaultValue`, and it
/// stays removable. The GDPR row's pre-check is [`gdpr_default`] itself, so the wizard's
/// offer and the rule it implements cannot drift.
fn legislation_choices(
    header_policy: Option<gdi_node_standalone_core::config::ProfileHeaderPolicy>,
    samples_total: usize,
) -> Vec<(&'static str, &'static str, bool)> {
    vec![
        ("EHDS: Regulation (EU) 2025/327", fields::EHDS_ELI, true),
        (
            "GDPR: Regulation (EU) 2016/679",
            fields::GDPR_ELI,
            gdpr_default(header_policy, samples_total),
        ),
    ]
}

/// The one "Applicable legislation" step: the EHDS/GDPR multi-select
/// ([`legislation_choices`]) followed by a free-entry loop for any other ELI or IRI,
/// de-duplicated, re-asked while the selection is empty.
///
/// `applicableLegislation` is 1..n, so an empty answer is re-asked rather than written —
/// the whole flow would otherwise abort at `validate_rendered` after the last question,
/// discarding every answer. Unticking the EHDS row is allowed and warns here with the
/// same words `build` will use, so the operator sees the consequence at the point of
/// choice rather than one command later.
///
/// The free-entry prompt takes a blank answer as "finish", so a mis-tapped yes on
/// "Add another ...?" is one Enter to escape: the validator would otherwise reject the
/// empty string, `dialoguer` would re-ask forever, and Ctrl-C — which discards the whole
/// run — would be the only way out. A typed entry that is already listed is reported
/// rather than silently swallowed by the de-duplication.
///
/// # Errors
///
/// Returns a [`ToolError`] on a prompt failure or an IRI the validator rejects.
fn prompt_applicable_legislation(
    p: &dyn Prompter,
    header_policy: Option<gdi_node_standalone_core::config::ProfileHeaderPolicy>,
    samples_total: usize,
) -> Result<Vec<String>, ToolError> {
    let choices = legislation_choices(header_policy, samples_total);
    let labels: Vec<String> = choices.iter().map(|(l, _, _)| (*l).to_owned()).collect();
    let checked: Vec<bool> = choices.iter().map(|(_, _, c)| *c).collect();
    // The context for both prompts of this step, said once above them: what the answers
    // are, that the EHDS row may be dropped, and what an extra entry should look like.
    // There is no per-country suggestion list: national gazettes have odd URL shapes, so a
    // curated list would be wrong somewhere.
    crate::output::progress(&format!(
        "  EU ELI IRIs, e.g. {}. The EHDS row may be unticked; build then warns, and \
         `--strict` fails on that warning.",
        fields::EHDS_ELI
    ));
    loop {
        let chosen = p.multiselect(
            "Applicable legislation (Space toggles, Enter confirms)",
            &labels,
            &checked,
        )?;
        let mut iris: Vec<String> = chosen
            .iter()
            .filter_map(|&i| choices.get(i))
            .map(|(_, iri, _)| (*iri).to_owned())
            .collect();
        // Free entry, using the same "Add another ...?" confirm the VCF step uses. The
        // blank answer is the way out of a mis-tapped yes, and de-duplication happens
        // here — at the point of entry — so it can say so instead of dropping the value.
        while p.confirm("Add another legislation ELI or IRI?", false)? {
            let answer = p.input_validated(
                "Enter another ELI or IRI (leave empty to finish)",
                None,
                &|s| {
                    if s.trim().is_empty() {
                        return Ok(());
                    }
                    fields::resolve_iri("applicableLegislation", s).map(|_| ())
                },
            )?;
            let entry = answer.trim();
            if entry.is_empty() {
                break;
            }
            if iris.iter().any(|iri| iri == entry) {
                // `progress`, not `note`: a note is `-v`-only, and the answer to "why is
                // what I just typed not in the document?" has to be visible by default.
                crate::output::progress(&format!(
                    "  already listed: {}; not added twice",
                    crate::output::Untrusted(entry)
                ));
            } else {
                iris.push(entry.to_owned());
            }
        }
        if iris.is_empty() {
            crate::output::warn(
                "warning: applicableLegislation needs at least one entry; tick one or add your own",
            );
            continue;
        }
        if !iris.iter().any(|iri| iri == fields::EHDS_ELI) {
            crate::output::warn(&format!(
                "warning: {}",
                gdi_node_standalone_core::validate_pkg::ehds_absent_warning()
            ));
        }
        return Ok(iris);
    }
}

/// Prompt one IRI from a curated `(label, IRI)` list, with a trailing "Other (enter IRI)"
/// escape that asks for a validated IRI under `field` instead.
///
/// # Errors
///
/// Returns a [`ToolError`] on a failed prompt.
fn prompt_curated_iri(
    p: &dyn Prompter,
    prompt: &str,
    iri_prompt: &str,
    field: &str,
    suggestions: &[(&str, &str)],
) -> Result<String, ToolError> {
    let mut labels: Vec<String> = suggestions.iter().map(|(l, _)| (*l).to_owned()).collect();
    labels.push("Other (enter IRI)".to_owned());
    let idx = p.select(prompt, &labels, 0)?;
    match suggestions.get(idx) {
        Some((_, iri)) => Ok((*iri).to_owned()),
        None => p.input_validated(iri_prompt, None, &|s| {
            fields::resolve_iri(field, s).map(|_| ())
        }),
    }
}

/// An optional free-text value (empty → `None`).
///
/// # Errors
///
/// Returns a [`ToolError`] on a failed prompt.
fn optional_text(p: &dyn Prompter, prompt: &str) -> Result<Option<String>, ToolError> {
    let s = p.input(prompt, None, true)?;
    Ok(if s.trim().is_empty() {
        None
    } else {
        Some(s.trim().to_owned())
    })
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

    #[test]
    fn no_tool_authored_package_ships_a_cohort_size_of_zero() {
        // An active `numberOfUniqueIndividuals: 0` is a valid cohort size, so a package
        // carrying it advertises zero subjects and `--strict` passes it silently, whereas an
        // absent field makes the recommended-field-absent path warn. Both renderers, `init`
        // and the wizard, are checked here, so neither can ship the active field alone.
        let has_active = |body: &str| {
            body.lines()
                .any(|l| l.trim_start().starts_with("numberOfUniqueIndividuals:"))
        };

        // Renderer 1: the `init` scaffold.
        let dir = tempfile::tempdir().unwrap();
        let scaffold = dir.path().join("package.yaml");
        crate::commands::cmd_init::write_template(
            &scaffold,
            false,
            r#"catalog: "REPLACE: catalog name""#,
        )
        .unwrap();
        let body = std::fs::read_to_string(&scaffold).unwrap();
        assert!(
            !has_active(&body),
            "init scaffold ships an active 0:\n{body}"
        );
        assert!(
            body.contains("numberOfUniqueIndividuals"),
            "the field must still be documented (commented) so a provider knows to set it"
        );

        // Renderer 2: the wizard's greenfield template, with the operator declining to
        // supply a cohort size (which is what pressing Enter must now mean).
        let mut v = sample_values();
        v.number_of_unique_individuals = None;
        let rendered = render_template(&v);
        assert!(
            !has_active(&rendered),
            "wizard render ships an active 0:\n{rendered}"
        );

        // And a real answer is still emitted.
        v.number_of_unique_individuals = Some(1234);
        assert!(render_template(&v).contains("numberOfUniqueIndividuals: 1234"));
    }

    #[test]
    fn pressing_enter_at_the_cohort_prompt_records_nothing() {
        // The prompt offered `Some("0")`, so an operator who answered yes to "Record cohort
        // size?" and then pressed Enter published `numberOfUniqueIndividuals: 0`.
        use crate::wizard::prompts::ScriptedPrompter;
        let p = ScriptedPrompter::new()
            .with_inputs(vec![""])
            .with_confirms(vec![true]);
        assert_eq!(
            prompt_cohort_size(&p).unwrap(),
            None,
            "a blank answer must record nothing, not a cohort of zero"
        );

        let p = ScriptedPrompter::new()
            .with_inputs(vec!["1234"])
            .with_confirms(vec![true]);
        assert_eq!(prompt_cohort_size(&p).unwrap(), Some(1234));

        // Declining skips the prompt entirely.
        let p = ScriptedPrompter::new().with_confirms(vec![false]);
        assert_eq!(prompt_cohort_size(&p).unwrap(), None);
    }

    #[test]
    fn the_gdpr_default_flips_exactly_when_identifiers_would_ship() {
        use gdi_node_standalone_core::config::ProfileHeaderPolicy as P;
        // D-3: default yes only when the profile ships identifiers and a source has any.
        assert!(gdpr_default(Some(P::WithIdentifiers), 11));
        assert!(!gdpr_default(Some(P::WithIdentifiers), 0));
        assert!(!gdpr_default(Some(P::Minimal), 11));
        assert!(!gdpr_default(None, 11));
    }

    /// The legislation menu's pre-ticks: EHDS always, removable but never absent, and GDPR
    /// exactly on `gdpr_default`. The rule is read from that function rather than restated,
    /// so this asserts the wiring;
    /// `the_gdpr_default_flips_exactly_when_identifiers_would_ship` asserts the rule.
    #[test]
    fn the_legislation_menu_pre_ticks_ehds_always_and_gdpr_by_the_rule() {
        use gdi_node_standalone_core::config::ProfileHeaderPolicy as P;
        for (policy, samples) in [
            (None, 0),
            (None, 11),
            (Some(P::Minimal), 11),
            (Some(P::WithIdentifiers), 0),
            (Some(P::WithIdentifiers), 11),
        ] {
            let rows = legislation_choices(policy, samples);
            assert_eq!(
                rows.len(),
                2,
                "the menu is EHDS + GDPR; extras are free entry"
            );
            assert_eq!(rows[0].1, fields::EHDS_ELI);
            assert!(rows[0].2, "the EHDS row is always pre-ticked");
            assert_eq!(rows[1].1, fields::GDPR_ELI);
            assert_eq!(rows[1].2, gdpr_default(policy, samples));
        }
    }

    /// The step is one multi-select plus a free-entry loop: what is ticked is kept, what
    /// is typed is appended and validated, a duplicate of an already-listed entry is
    /// reported and not added twice, and the pre-ticks reach the prompter (a step that
    /// built the rows and then passed `&[]` would look identical to a scripted answer
    /// without this).
    #[test]
    fn the_legislation_step_collects_ticks_and_typed_entries() {
        use crate::wizard::prompts::ScriptedPrompter;
        use gdi_node_standalone_core::config::ProfileHeaderPolicy as P;
        // Tick both rows, then type one more ELI — and a duplicate of the EHDS row.
        let p = ScriptedPrompter::new()
            .with_multiselects(vec![vec![0, 1]])
            .with_confirms(vec![true, true, false])
            .with_inputs(vec![
                "https://www.riigiteataja.ee/akt/128122023011",
                fields::EHDS_ELI,
            ]);
        let iris = prompt_applicable_legislation(&p, Some(P::WithIdentifiers), 11).unwrap();
        assert_eq!(
            iris,
            [
                fields::EHDS_ELI.to_owned(),
                fields::GDPR_ELI.to_owned(),
                "https://www.riigiteataja.ee/akt/128122023011".to_owned(),
            ],
            "the duplicate EHDS entry is reported, not appended a second time"
        );
        let ticks = p.seen_multiselect_defaults();
        assert_eq!(
            ticks,
            vec![(
                "Applicable legislation (Space toggles, Enter confirms)".to_owned(),
                vec![true, true]
            )],
            "the data-derived pre-ticks must reach the menu"
        );

        // No profile policy: the GDPR row opens unticked.
        let p = ScriptedPrompter::new()
            .with_multiselects(vec![vec![0]])
            .with_confirms(vec![false]);
        assert_eq!(
            prompt_applicable_legislation(&p, None, 11).unwrap(),
            [fields::EHDS_ELI.to_owned()]
        );
        assert_eq!(p.seen_multiselect_defaults()[0].1, vec![true, false]);
    }

    /// Unticking EHDS is allowed and the result is written without it. An empty selection
    /// is re-asked rather than written: `applicableLegislation` is 1..n, so writing it would
    /// abort the whole flow at the final validation and discard every answer.
    #[test]
    fn the_legislation_step_allows_dropping_ehds_but_not_emptiness() {
        use crate::wizard::prompts::ScriptedPrompter;
        // Tick only the GDPR row.
        let p = ScriptedPrompter::new()
            .with_multiselects(vec![vec![1]])
            .with_confirms(vec![false]);
        assert_eq!(
            prompt_applicable_legislation(&p, None, 0).unwrap(),
            [fields::GDPR_ELI.to_owned()]
        );

        // Nothing ticked and nothing typed: re-asked, then answered.
        let p = ScriptedPrompter::new()
            .with_multiselects(vec![vec![], vec![0]])
            .with_confirms(vec![false, false]);
        assert_eq!(
            prompt_applicable_legislation(&p, None, 0).unwrap(),
            [fields::EHDS_ELI.to_owned()]
        );

        // A typed entry that is not an IRI is rejected at its prompt.
        let p = ScriptedPrompter::new()
            .with_multiselects(vec![vec![0]])
            .with_confirms(vec![true])
            .with_inputs(vec!["EHDS"]);
        assert!(prompt_applicable_legislation(&p, None, 0).is_err());
    }

    /// A mis-tapped yes on "Add another ...?" must be escapable with one Enter. The blank
    /// answer finishes the loop instead of failing the validator — at a real terminal the
    /// rejected empty string is simply re-asked, so without this the only way out of the
    /// question is Ctrl-C, which discards every answer given so far.
    #[test]
    fn a_blank_answer_leaves_the_add_another_loop() {
        use crate::wizard::prompts::ScriptedPrompter;
        // Yes by mistake, then Enter on the empty prompt: the ticked row is the result and
        // the "Add another ...?" confirm is not asked again (a second `true` in the queue
        // would be consumed if it were, and the run would then go dry on inputs).
        let p = ScriptedPrompter::new()
            .with_multiselects(vec![vec![0]])
            .with_confirms(vec![true])
            .with_inputs(vec![""]);
        assert_eq!(
            prompt_applicable_legislation(&p, None, 0).unwrap(),
            [fields::EHDS_ELI.to_owned()]
        );
        // The escape prompt has to say it is an escape.
        assert!(
            p.seen_prompts()
                .iter()
                .any(|s| s == "Enter another ELI or IRI (leave empty to finish)"),
            "{:?}",
            p.seen_prompts()
        );

        // Blank on the first round with nothing ticked still re-asks: escaping the loop is
        // not a way to author an empty `applicableLegislation`.
        let p = ScriptedPrompter::new()
            .with_multiselects(vec![vec![], vec![0]])
            .with_confirms(vec![true, false])
            .with_inputs(vec![""]);
        assert_eq!(
            prompt_applicable_legislation(&p, None, 0).unwrap(),
            [fields::EHDS_ELI.to_owned()]
        );
    }

    /// The `conformsTo` menu opens with nothing ticked, and an empty answer yields an empty
    /// list, which omits the field. Pre-ticking a value would stamp the same standard on
    /// every dataset.
    #[test]
    fn the_conforms_to_step_pre_ticks_nothing_and_may_be_skipped() {
        use crate::wizard::prompts::ScriptedPrompter;
        let p = ScriptedPrompter::new().with_multiselects(vec![vec![]]);
        assert!(prompt_conforms_to(&p).unwrap().is_empty());
        let (prompt, ticks) = p.seen_multiselect_defaults().remove(0);
        assert!(
            prompt.starts_with("Conforms to (GDI standards)"),
            "{prompt}"
        );
        assert_eq!(ticks, vec![false; ticks.len()], "nothing may be pre-ticked");
        assert_eq!(
            ticks.len(),
            gdi_node_standalone_core::validate_pkg::CONFORMS_TO.len()
        );

        // A choice maps to the closed-set IRI in menu order.
        let p = ScriptedPrompter::new().with_multiselects(vec![vec![1]]);
        assert_eq!(
            prompt_conforms_to(&p).unwrap(),
            ["http://data.gdi.eu/core/p2/1MGCompliant".to_owned()]
        );
    }

    #[test]
    fn keywords_are_deduplicated_and_capped_at_the_prompt() {
        // A repeated keyword is written once.
        assert_eq!(
            parse_keywords("asdf, genomics,asdf , ,genomics,af"),
            vec!["asdf".to_owned(), "genomics".to_owned(), "af".to_owned()]
        );
        assert!(validate_keywords("a,b,c").is_ok());
        assert!(validate_keywords("").is_ok(), "blank means no keywords");
        let too_long = "x".repeat(65);
        assert!(
            validate_keywords(&format!("ok,{too_long}")).is_err(),
            "a keyword over core's cap is re-asked at the prompt"
        );
    }

    #[test]
    fn compression_base_identifies_same_data_twins() {
        // The twin shape: one path, two compressions — same base.
        assert_eq!(
            compression_base("/d/COVID.vcf"),
            compression_base("/d/COVID.vcf.gz")
        );
        assert_eq!(compression_base("/d/x.vcf.bgz"), "/d/x.vcf");
        // Same name in different directories is not a twin (per-population split).
        assert_ne!(
            compression_base("/pop1/chr1.vcf.gz"),
            compression_base("/pop2/chr1.vcf.gz")
        );
        // Distinct stems stay distinct.
        assert_ne!(
            compression_base("/d/chr1.vcf.gz"),
            compression_base("/d/chr2.vcf.gz")
        );
    }

    #[test]
    fn fixup_validates_a_typed_field_at_its_own_prompt() {
        // A typed marker must be rejected at its own prompt, not in a lump by
        // `validate_rendered` after the last question, which writes nothing and loses every
        // answer. The fix-up path therefore wires `resolve_iri`, `resolve_assembly` and
        // `resolve_email` rather than validating every marker as merely non-empty.
        let iri = validator_for("license", "license IRI");
        assert!(iri("not-an-iri").is_err(), "a license must be an IRI");
        assert!(iri("https://example.org/lic").is_ok());

        let asm = validator_for("reference", "GRCh38");
        assert!(asm("hg38").is_err(), "assembly is a closed vocabulary");
        assert!(asm("GRCh38").is_ok());

        let email = validator_for("hasEmail", "mailto:x@example.org");
        assert!(email("data@example.org").is_err(), "mailto: is required");
        assert!(email("mailto:data@example.org").is_ok());

        // Untyped keys keep the non-empty rule: the fallback, not the universal rule.
        // A bare LIST scalar inherits the mapping key that opened the list, so the
        // template's own `healthCategory:` / `applicableLegislation:` blocks are
        // validated as what they are. Reading the key from the whole line instead
        // yielded `"REPLACE` (the marker text carries the first ':'), which fell through
        // to the non-empty fallback — the typed validators never ran on exactly the two
        // fields `init` writes as list scalars.
        assert_eq!(
            marker_key(
                r#"    - "REPLACE: http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic""#,
                "healthCategory"
            ),
            "healthCategory"
        );
        assert_eq!(
            marker_key(r#"  license: "REPLACE: x""#, "metadata"),
            "license"
        );
        assert_eq!(
            marker_key(r#"    - name: "REPLACE: org""#, "creator"),
            "name"
        );
        assert_eq!(block_key("  healthCategory:"), Some("healthCategory"));
        assert_eq!(block_key(r#"  title: "REPLACE: t""#), None);
        assert_eq!(block_key("    - GRCh38"), None);
        assert_eq!(block_key("  # a comment:"), None);
        let closed = validator_for("healthCategory", "an IRI");
        assert!(
            closed("http://data.gdi.eu/core/p2/HealthCategoryHumanProteomic").is_err(),
            "a healthCategory outside the vendored closed set must fail AT ITS PROMPT"
        );
        assert!(closed("http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic").is_ok());
        let eli = validator_for("applicableLegislation", "an ELI");
        assert!(eli("EHDS").is_err(), "legislation entries are IRIs");
        assert!(eli("http://data.europa.eu/eli/reg/2025/327/oj").is_ok());

        let free = validator_for("title", "Dataset title");
        assert!(free("   ").is_err());
        assert!(free("A cohort").is_ok());
    }

    /// Restores the process CWD on drop — `set_current_dir` is process-global, so a panic
    /// mid-test must not leave every later test in a deleted directory.
    struct RestoreCwd(std::path::PathBuf);
    impl Drop for RestoreCwd {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }

    #[test]
    #[serial_test::serial(env)]
    fn a_relative_vcf_answer_is_resolved_against_the_cwd_the_operator_typed_it_in() {
        // The wizard previewed the VCF (and sampled the floor impact) through the CWD, then
        // wrote the answer verbatim into package.yaml — where `build` resolves relative
        // paths against the YAML's own directory. Run the wizard anywhere but the package
        // dir and those are two different files: the preview reports on one, the build
        // reads the other, or fails outright. Resolve once, at the point of entry.
        let dir = tempfile::tempdir().unwrap();
        let vcf = dir.path().join("cohort.vcf");
        std::fs::write(&vcf, b"##fileformat=VCFv4.2\n").unwrap();

        let _restore = RestoreCwd(std::env::current_dir().unwrap());
        std::env::set_current_dir(dir.path()).unwrap();

        let resolved = resolve_vcf_input("cohort.vcf");
        let resolved = std::path::Path::new(&resolved);
        assert!(
            resolved.is_absolute(),
            "a CWD-relative answer must not be carried into the YAML as-is: {}",
            resolved.display()
        );
        assert!(
            resolved.is_file(),
            "the resolved path must still name the file the operator meant: {}",
            resolved.display()
        );

        // A path that does not resolve is handed back untouched, so the preview reports the
        // operator's own spelling rather than a canonicalization error about it.
        assert_eq!(resolve_vcf_input("nope.vcf"), "nope.vcf");
    }
    use super::*;
    use gdi_node_standalone_core::model::PackageYaml;
    use gdi_node_standalone_core::validate_pkg::validate_package_collect_all;

    fn sample_values() -> AuthorValues {
        AuthorValues {
            prefix: "GOE".into(),
            org: "UTARTU".into(),
            catalog: "gdi-aggregated".into(),
            title: "Allele frequencies (synthetic data)".into(),
            description: "A test dataset.".into(),
            access_rights_iri: crate::wizard::fields::access_right_iri(0).into(),
            license_iri: "https://creativecommons.org/licenses/by/4.0/".into(),
            creator: "Test Institute".into(),
            health_category_iris: vec![
                "http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic".into(),
            ],
            conforms_to_iris: Vec::new(),
            applicable_legislation: vec![crate::wizard::fields::EHDS_ELI.into()],
            keywords: vec!["allele-frequency".into(), "genomics".into()],
            number_of_unique_individuals: Some(1200),
            af_source: Some("Test cohort".into()),
            af_source_reference: Some("https://example.org/".into()),
            vcf_paths: vec!["data/test.vcf.gz".into()],
            assembly: "GRCh38".into(),
            block_range: 10_000_000,
            min_allele_count: 0,
            synthetic: true,
        }
    }

    /// Every legislation entry the step collected is written, in order — the review
    /// (which prints the whole document) therefore lists them all, and a third, freely
    /// typed ELI is not silently dropped the way a `cite_gdpr: bool` would have dropped it.
    #[test]
    fn every_legislation_entry_reaches_the_written_document() {
        let mut v = sample_values();
        let without = render_template(&v);
        assert!(!without.contains(crate::wizard::fields::GDPR_ELI));
        v.applicable_legislation = vec![
            crate::wizard::fields::EHDS_ELI.to_owned(),
            crate::wizard::fields::GDPR_ELI.to_owned(),
            "https://www.riigiteataja.ee/akt/128122023011".to_owned(),
        ];
        let with = render_template(&v);
        let pkg: PackageYaml = serde_saphyr::from_str(&with).unwrap();
        assert_eq!(
            pkg.metadata.applicable_legislation,
            v.applicable_legislation
        );
        assert!(validate_package_collect_all(&pkg, None).is_valid());

        // The EHDS row is removable: the document is still valid, and the shared validator
        // says so with a warning rather than an error.
        v.applicable_legislation = vec![crate::wizard::fields::GDPR_ELI.to_owned()];
        let pkg: PackageYaml = serde_saphyr::from_str(&render_template(&v)).unwrap();
        let report = validate_package_collect_all(&pkg, None);
        assert!(report.is_valid(), "errors: {:?}", report.errors);
        assert!(
            report
                .warnings
                .contains(&gdi_node_standalone_core::validate_pkg::ehds_absent_warning()),
            "{:?}",
            report.warnings
        );
    }

    /// `conformsTo` is written only when the operator ticked something, since there is no
    /// node-level default, and every value is one the node's closed set accepts.
    #[test]
    fn conforms_to_is_written_only_when_chosen() {
        let mut v = sample_values();
        assert!(
            !render_template(&v).contains("conformsTo"),
            "an empty selection must omit the field entirely"
        );
        v.conforms_to_iris = gdi_node_standalone_core::validate_pkg::CONFORMS_TO
            .iter()
            .map(|iri| (*iri).to_owned())
            .collect();
        let yaml = render_template(&v);
        let pkg: PackageYaml = serde_saphyr::from_str(&yaml).unwrap();
        assert_eq!(pkg.metadata.conforms_to, Some(v.conforms_to_iris.clone()));
        let report = validate_package_collect_all(&pkg, None);
        assert!(report.is_valid(), "errors: {:?}", report.errors);
    }

    #[test]
    fn rendered_template_parses_and_validates() {
        let yaml = render_template(&sample_values());
        // 1. It parses as the package model (no YAML serializer needed).
        let pkg: PackageYaml = serde_saphyr::from_str(&yaml).expect("rendered template parses");
        // 2. It passes the holistic validator (the drift guard: wizard output is buildable).
        let result = validate_package_collect_all(&pkg, None);
        assert!(
            result.is_valid(),
            "rendered package.yaml must validate; errors: {:?}",
            result.errors
        );
        // 3. No REPLACE: markers remain.
        assert!(!yaml.contains("REPLACE:"), "no placeholders remain");
        // 4. Synthetic type IRI present when synthetic=true.
        assert!(yaml.contains(crate::wizard::fields::SYNTHETIC_TYPE_IRI));
    }

    #[test]
    fn control_char_in_title_still_renders_valid_yaml() {
        // A pasted control or non-printable char in a free-text field must render valid
        // YAML with `\xNN` escaping, not the Rust `{:?}` `\u{85}` form that YAML rejects.
        let mut v = sample_values();
        v.title = "Cohort\u{85}\tpanel\"quoted\\".to_owned();
        let yaml = render_template(&v);
        // Correct YAML escaping (`\xNN`), not the Rust `\u{85}` form YAML rejects.
        assert!(
            yaml.contains("\\x85"),
            "the C1 control must be YAML \\xNN-escaped, got:\n{yaml}"
        );
        let _pkg: PackageYaml = serde_saphyr::from_str(&yaml)
            .expect("a control char in the title must still yield parseable YAML");
    }

    #[test]
    fn non_synthetic_omits_type() {
        let mut v = sample_values();
        v.synthetic = false;
        let yaml = render_template(&v);
        assert!(!yaml.contains("type:"), "type omitted for non-synthetic");
        let pkg: PackageYaml = serde_saphyr::from_str(&yaml).unwrap();
        assert!(validate_package_collect_all(&pkg, None).is_valid());
    }

    #[test]
    fn replace_markers_detected() {
        let yaml = "metadata:\n  org: \"REPLACE: ORG\"\n  title: \"ok\"\n  license: \"REPLACE: license IRI\"\n";
        let m = replace_markers(yaml);
        assert_eq!(m.len(), 2);
        assert!(m.iter().any(|l| l.contains("org")));
        assert!(m.iter().any(|l| l.contains("license")));
    }

    /// Verify the build-time floor question states its unit at the point of choice —
    /// the note printed above the prompt says it counts ALLELES, not people — since
    /// that caveat otherwise lives only in the node's config example, which a provider
    /// never opens. (The wording moved from one 60-word prompt into a two-line note +
    /// short prompt; the invariant is unchanged: the unit is stated where the number is
    /// typed.)
    #[test]
    fn the_floor_prompt_states_the_unit_where_the_choice_is_made() {
        assert!(
            FLOOR_NOTE.contains("ALLELES") && FLOOR_NOTE.contains("not people"),
            "the floor note must state its unit: {FLOOR_NOTE}"
        );
        assert!(
            FLOOR_PROMPT.contains("0 = publish everything"),
            "the prompt must say what 0 means: {FLOOR_PROMPT}"
        );
    }

    #[test]
    fn the_wizard_asks_for_the_floor_instead_of_hard_coding_it_off() {
        use crate::wizard::prompts::ScriptedPrompter;
        let p = ScriptedPrompter::new().with_inputs(vec!["5"]);
        assert_eq!(prompt_min_allele_count(&p).unwrap(), 5);
    }

    #[test]
    fn an_empty_floor_answer_means_no_suppression() {
        use crate::wizard::prompts::ScriptedPrompter;
        let p = ScriptedPrompter::new().with_inputs(vec!["0"]);
        assert_eq!(prompt_min_allele_count(&p).unwrap(), 0);
    }

    #[test]
    fn a_non_numeric_floor_is_rejected() {
        use crate::wizard::prompts::ScriptedPrompter;
        let p = ScriptedPrompter::new().with_inputs(vec!["five"]);
        assert!(prompt_min_allele_count(&p).is_err());
    }

    /// Verify that `author_fixup` correctly handles all three marker shapes present
    /// in the real `cmd_init` template: simple `key: "REPLACE: ..."`, named-list
    /// `- name: "REPLACE: ..."` (creator), and bare-list `- "REPLACE: ..."` (healthCategory
    /// and VCF path).
    #[test]
    fn fixup_handles_real_init_template() {
        use crate::wizard::prompts::ScriptedPrompter;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.yaml");
        // Write the real init template (no profile → all REPLACE markers, static
        // catalog placeholder).
        crate::commands::cmd_init::write_template(
            &path,
            false,
            r#"catalog: "REPLACE: catalog name""#,
        )
        .unwrap();
        let original = std::fs::read_to_string(&path).unwrap();
        let markers = replace_markers(&original);
        let n = markers.len();
        // The init template must have exactly these 11 REPLACE markers (top-to-bottom):
        //   1  prefix           2  org                3  catalog
        //   4  title            5  description        6  accessRights
        //   7  license          8  creator name       9  healthCategory (bare list)
        //  10  VCF reference   11  VCF path (bare)
        //
        // `config.afSource` / `afSourceReference` are not markers here. They are optional
        // fields and are rendered commented out, like `preciseReference`,
        // `internalId` and `pastVersion`: an uncommented placeholder on an optional field
        // is one a provider can legitimately leave alone.
        assert_eq!(n, 11, "expected 11 REPLACE markers; got {n}: {markers:?}");

        // Valid answers in top-to-bottom file order. The VCF marker goes through the
        // source prompt, so it must name a file that exists and reads as a VCF.
        let access_rights_iri = crate::wizard::fields::access_right_iri(0);
        let vcf = test_util::covid_vcf_path();
        let answers: Vec<&str> = vec![
            "GOE",                                                   // 1  prefix
            "UTARTU",                                                // 2  org
            "gdi-aggregated",                                        // 3  catalog
            "Test allele frequencies",                               // 4  title
            "A test dataset.",                                       // 5  description
            access_rights_iri,                                       // 6  accessRights
            "https://creativecommons.org/licenses/by/4.0/",          // 7  license
            "Test Institute",                                        // 8  creator name
            "http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic", // 9  healthCategory
            "GRCh38",                                                // 10 VCF reference
            vcf.to_str().unwrap(),                                   // 11 VCF path
        ];
        assert_eq!(answers.len(), n, "one answer per marker");
        let p = ScriptedPrompter::new()
            .with_inputs(answers)
            .with_confirms(vec![false]) // add another VCF? no
            .with_selects(vec![0]); // review: write it
        author_fixup(&p, &path).unwrap();

        let fixed = std::fs::read_to_string(&path).unwrap();
        assert!(!fixed.contains("REPLACE:"), "all markers must be filled");
        assert!(
            fixed.contains(&yaml_quote(vcf.to_str().unwrap())),
            "the VCF answer is written resolved, as the source prompt resolved it:\n{fixed}"
        );
        // The fixed YAML must round-trip through the model and pass holistic validation.
        let pkg: gdi_node_standalone_core::model::PackageYaml =
            serde_saphyr::from_str(&fixed).unwrap();
        let result =
            gdi_node_standalone_core::validate_pkg::validate_package_collect_all(&pkg, None);
        assert!(
            result.is_valid(),
            "fixed package must be valid; errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn fixup_replaces_markers_and_validates() {
        use crate::wizard::prompts::ScriptedPrompter;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.yaml");
        // A template with two REPLACE markers (org + license); everything else valid.
        let mut v = sample_values();
        v.org = "REPLACE: ORG".into();
        v.license_iri = "REPLACE: license IRI".into();
        std::fs::write(&path, render_template(&v)).unwrap();

        // The wizard will ask, in marker order, for replacements — then for the review.
        let p = ScriptedPrompter::new()
            .with_inputs(vec![
                "UTARTU",
                "https://creativecommons.org/licenses/by/4.0/",
            ])
            .with_selects(vec![0]); // review: write it
        author_fixup(&p, &path).unwrap();

        let fixed = std::fs::read_to_string(&path).unwrap();
        assert!(!fixed.contains("REPLACE:"), "all markers filled");
        let pkg: PackageYaml = serde_saphyr::from_str(&fixed).unwrap();
        assert!(validate_package_collect_all(&pkg, None).is_valid());
        assert!(
            path.with_extension("yaml.bak").exists()
                || dir.path().join("package.yaml.bak").exists()
        );
    }

    #[test]
    fn fixup_control_char_answer_yields_parseable_yaml() {
        // The fixup path: a non-printable char in a fill-in answer must render valid YAML.
        // `{:?}` quoting produces the Rust `\u{85}` form, which YAML rejects, so
        // `author_fixup` could not parse its own output. `yaml_quote` emits `\x85`.
        use crate::wizard::prompts::ScriptedPrompter;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.yaml");
        // Exactly one REPLACE marker (the title); every other field is valid.
        let mut v = sample_values();
        v.title = "REPLACE: title".into();
        std::fs::write(&path, render_template(&v)).unwrap();

        let p = ScriptedPrompter::new()
            .with_inputs(vec!["Cohort\u{85}panel"])
            .with_selects(vec![0]); // review: write it
        match author_fixup(&p, &path) {
            Ok(_) => {
                let fixed = std::fs::read_to_string(&path).unwrap();
                assert!(
                    fixed.contains("\\x85"),
                    "the C1 control must be YAML \\xNN-escaped, got:\n{fixed}"
                );
                let _pkg: PackageYaml =
                    serde_saphyr::from_str(&fixed).expect("the fixed-up package.yaml must parse");
            }
            Err(e) => {
                // A parse failure here would mean the renderer emitted invalid YAML; a
                // semantic-validation rejection is a different error.
                assert!(
                    !e.to_string().contains("did not parse"),
                    "a control-char answer must still yield parseable YAML, got: {e}"
                );
            }
        }
    }

    #[test]
    fn natural_order_reads_chromosome_names_like_a_person() {
        use std::cmp::Ordering;
        let mut names = vec![
            "chr10.vcf",
            "chr2.vcf",
            "chr1.vcf",
            "chrX.vcf",
            "chr1.vcf.gz",
        ];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(
            names,
            [
                "chr1.vcf",
                "chr1.vcf.gz",
                "chr2.vcf",
                "chr10.vcf",
                "chrX.vcf"
            ]
        );
        assert_eq!(natural_cmp("a2", "a10"), Ordering::Less);
        assert_eq!(natural_cmp("007", "7"), Ordering::Equal);
        assert_eq!(natural_cmp("b", "a"), Ordering::Greater);
    }

    #[test]
    fn list_vcfs_keeps_only_vcfs_in_natural_order() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "chr10.vcf.gz",
            "chr2.VCF",
            "chr1.vcf",
            "notes.txt",
            "chr3.vcf.tbi",
        ] {
            std::fs::write(dir.path().join(name), b"").unwrap();
        }
        // A directory is never a source, whatever it is called.
        std::fs::create_dir(dir.path().join("sub.vcf")).unwrap();
        let listed: Vec<String> = list_vcfs(dir.path())
            .unwrap()
            .iter()
            .map(|p| file_name_of(p))
            .collect();
        assert_eq!(listed, ["chr1.vcf", "chr2.VCF", "chr10.vcf.gz"]);
    }

    #[test]
    fn the_source_validator_wants_a_file_or_a_directory_with_vcfs() {
        let dir = tempfile::tempdir().unwrap();
        let as_str = |p: &Path| p.to_str().unwrap().to_owned();
        assert!(validate_vcf_source("").is_err());
        assert!(validate_vcf_source(&as_str(&dir.path().join("missing.vcf"))).is_err());
        assert!(
            validate_vcf_source(&as_str(dir.path())).is_err(),
            "an empty directory holds no VCF"
        );
        std::fs::write(dir.path().join("a.vcf"), b"").unwrap();
        assert!(validate_vcf_source(&as_str(dir.path())).is_ok());
        assert!(validate_vcf_source(&as_str(&dir.path().join("a.vcf"))).is_ok());
    }

    #[test]
    fn catalog_rows_show_the_title_only_when_it_adds_something() {
        assert_eq!(catalog_label("goe", "goe"), "goe");
        assert_eq!(catalog_label("goe", ""), "goe");
        assert_eq!(
            catalog_label("goe", "Genome of Europe"),
            "goe: Genome of Europe"
        );
    }

    /// The catalog list carries a refresh row that re-fetches and re-asks; with nothing
    /// pinned the refresh is offered first; a failed refresh keeps the list and re-asks.
    #[test]
    fn the_catalog_prompt_refreshes_from_the_node_and_re_asks() {
        use crate::wizard::prompts::ScriptedPrompter;
        let pinned = || BTreeMap::from([("goe".to_owned(), "goe".to_owned())]);
        let fetched = || -> Result<BTreeMap<String, String>, ToolError> {
            Ok(BTreeMap::from([
                ("fresh".to_owned(), "Fresh".to_owned()),
                ("goe".to_owned(), "goe".to_owned()),
            ]))
        };
        let refresh: &dyn Fn() -> Result<BTreeMap<String, String>, ToolError> = &fetched;

        // Pinned [goe] + the refresh row at index 1: refresh, then pick "fresh" (index 0 of
        // the new, sorted list).
        let ctx = AuthorContext {
            catalogs: pinned(),
            org: None,
            refresh_catalogs: Some(refresh),
            header_policy: None,
        };
        let p = ScriptedPrompter::new().with_selects(vec![1, 0]);
        assert_eq!(prompt_catalog(&p, &ctx).unwrap(), "fresh");

        // Nothing pinned: the refresh is offered first (yes), then the list is asked.
        let ctx = AuthorContext {
            catalogs: BTreeMap::new(),
            org: None,
            refresh_catalogs: Some(refresh),
            header_policy: None,
        };
        let p = ScriptedPrompter::new()
            .with_confirms(vec![true])
            .with_selects(vec![1]);
        assert_eq!(prompt_catalog(&p, &ctx).unwrap(), "goe");

        // Nothing pinned, refresh declined: free text.
        let p = ScriptedPrompter::new()
            .with_confirms(vec![false])
            .with_inputs(vec!["typed"]);
        assert_eq!(prompt_catalog(&p, &ctx).unwrap(), "typed");

        // A failing refresh keeps the pinned list and asks again.
        let failing =
            || -> Result<BTreeMap<String, String>, ToolError> { Err(ToolError::user("node down")) };
        let failing_ref: &dyn Fn() -> Result<BTreeMap<String, String>, ToolError> = &failing;
        let ctx = AuthorContext {
            catalogs: pinned(),
            org: None,
            refresh_catalogs: Some(failing_ref),
            header_policy: None,
        };
        let p = ScriptedPrompter::new().with_selects(vec![1, 0]);
        assert_eq!(prompt_catalog(&p, &ctx).unwrap(), "goe");

        // No node to refresh from: the list is exactly the pinned names, no extra row.
        let ctx = AuthorContext {
            catalogs: pinned(),
            org: None,
            refresh_catalogs: None,
            header_policy: None,
        };
        let p = ScriptedPrompter::new().with_selects(vec![0]);
        assert_eq!(prompt_catalog(&p, &ctx).unwrap(), "goe");
    }

    /// The review gate never writes an invalid edit: "Write" on a broken document is
    /// refused and re-offered, and what is accepted is the last valid edit. Abort discards.
    #[test]
    fn the_review_gate_accepts_only_a_valid_document() {
        use crate::wizard::prompts::ScriptedPrompter;
        let original = render_template(&sample_values());
        let retitled = original.replace("Allele frequencies (synthetic data)", "Reviewed title");
        assert_ne!(retitled, original, "the sample title must have been found");
        // edit → broken; write → refused; edit → retitled; write → accepted.
        let p = ScriptedPrompter::new()
            .with_selects(vec![1, 0, 1, 0])
            .with_editors(vec!["metadata: {}\n", retitled.as_str()]);
        assert_eq!(review_before_write(&p, original.clone()).unwrap(), retitled);

        let p = ScriptedPrompter::new().with_selects(vec![2]);
        let err = review_before_write(&p, original).unwrap_err();
        assert!(err.message.contains("discarded"), "{}", err.message);
    }

    #[test]
    fn a_multi_file_group_renders_one_entry_per_source() {
        let mut v = sample_values();
        v.vcf_paths = vec!["/data/chr1.vcf.gz".into(), "/data/chr2.vcf.gz".into()];
        let yaml = render_template(&v);
        let pkg: PackageYaml = serde_saphyr::from_str(&yaml).unwrap();
        assert_eq!(pkg.files[0].files.len(), 2, "{yaml}");
        assert!(validate_package_collect_all(&pkg, None).is_valid());
    }

    /// A directory answer expands to its VCFs (pre-checked, natural order), other files are
    /// ignored, and every path is written resolved.
    #[test]
    fn a_directory_answer_expands_to_its_vcfs_in_natural_order() {
        use crate::wizard::prompts::ScriptedPrompter;
        let dir = tempfile::tempdir().unwrap();
        let vcfs = dir.path().join("vcfs");
        std::fs::create_dir(&vcfs).unwrap();
        for name in ["chr10.vcf", "chr2.vcf", "chr1.vcf"] {
            std::fs::write(vcfs.join(name), test_util::covid_vcf_bytes()).unwrap();
        }
        std::fs::write(vcfs.join("README.txt"), b"not a vcf").unwrap();
        let p = ScriptedPrompter::new()
            .with_inputs(vec![vcfs.to_str().unwrap()])
            .with_multiselects(vec![vec![0, 1, 2]])
            .with_confirms(vec![false]); // add another? no
        let sources = collect_vcf_sources(&p).unwrap();
        let names: Vec<String> = sources
            .paths
            .iter()
            .map(|p| file_name_of(Path::new(p)))
            .collect();
        assert_eq!(names, ["chr1.vcf", "chr2.vcf", "chr10.vcf"]);
        assert!(
            sources.paths.iter().all(|p| Path::new(p).is_absolute()),
            "every path is resolved: {:?}",
            sources.paths
        );
        // The fixture's `##reference=GRCh38` line pre-selects the assembly.
        assert_eq!(sources.assembly_hint, Some("GRCh38"));
    }

    /// An unreadable source is not a "continue anyway?": the menu re-asks or aborts.
    #[test]
    fn an_unreadable_source_re_asks_or_aborts() {
        use crate::wizard::prompts::ScriptedPrompter;
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad.vcf");
        std::fs::write(&bad, b"this is not a VCF\n").unwrap();
        let good = test_util::covid_vcf_path();
        // bad → menu: re-enter (0) → good → done.
        let p = ScriptedPrompter::new()
            .with_inputs(vec![bad.to_str().unwrap(), good.to_str().unwrap()])
            .with_confirms(vec![false, false])
            .with_selects(vec![0]);
        let sources = collect_vcf_sources(&p).unwrap();
        assert_eq!(sources.paths.len(), 1);
        assert!(sources.paths[0].ends_with("COVID.monogneic.aggregate.AFs.GRCh38.vcf"));
        // bad → menu: abort (1).
        let p = ScriptedPrompter::new()
            .with_inputs(vec![bad.to_str().unwrap()])
            .with_confirms(vec![false])
            .with_selects(vec![1]);
        let err = collect_vcf_sources(&p).unwrap_err();
        assert!(err.message.contains("aborted"), "{}", err.message);
    }
}
