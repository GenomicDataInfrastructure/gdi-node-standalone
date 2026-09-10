//! The `init` command: scaffold a new `package.yaml` template.
//!
//! The generated template has the four sections (`metadata`, `files`, `internal`,
//! `config`). Required fields are `REPLACE:`-prefixed placeholders the provider must fill
//! in **except** `applicableLegislation`, which is pre-filled with the EHDS ELI (the one
//! required field with a sensible default — removable, at the cost of a `build` warning
//! that `--strict` fails on, and extendable with the GDPR or a national act), and
//! `license`, which is a `REPLACE:` placeholder so the provider chooses explicit terms.
//! Recommended fields (`keywords`, `numberOfUniqueIndividuals`) sit under their own
//! header; optional fields are shown commented out with example values.
//!
//! `build`/`validate` reject any remaining `REPLACE:` marker anywhere in the
//! document (see `core::validate_pkg`, a serde leaf walk rather than a per-field
//! list), so a freshly scaffolded template cannot be packaged until it is filled
//! in.

use std::fs;
use std::path::Path;

use crate::cli::InitArgs;
use crate::wizard::fields::{EHDS_ELI, GOE_AF_SOURCE, GOE_AF_SOURCE_REFERENCE};
use crate::{ToolError, profile};

/// The static `metadata.catalog` placeholder used when no profile catalog
/// allow-list is available to scaffold from.
const CATALOG_PLACEHOLDER: &str = r#"catalog: "REPLACE: catalog name""#;

/// The whole `healthCategory` comment block: the field's one-liner plus every IRI of
/// the closed set, one per continuation line.
///
/// Interpolated from `core`'s vendored constant, so a hand-author does not have to guess
/// the members the node accepts and a re-vendor updates the scaffold for free — the
/// wizard's own menu derives from the same source. The heading lives here rather than in
/// the template literal so the block costs the template exactly one line however many
/// categories the set grows to.
fn health_category_comment() -> String {
    format!(
        "GDI health category IRIs (list; 1..n). The CLOSED set the node accepts:\n  #   {}",
        gdi_node_standalone_core::validate_pkg::HEALTH_CATEGORIES.join("\n  #   ")
    )
}

/// The whole `conformsTo` comment block: the field's one-liner plus every IRI of the
/// closed set with the label the GDI shape gives it, one per continuation line.
///
/// Interpolated from `core`'s vendored constant and its labels for the same reason as
/// [`health_category_comment`]: the set is closed, since `build` rejects anything else,
/// and the three values differ only in capitalisation, so naming just one of them would
/// leave a hand-author guessing at the other two.
fn conforms_to_comment() -> String {
    use gdi_node_standalone_core::validate_pkg::{CONFORMS_TO, conforms_to_label};
    let rows: Vec<String> = CONFORMS_TO
        .iter()
        .map(|iri| format!("  #   - \"{iri}\"  # {}", conforms_to_label(iri)))
        .collect();
    let head = "conformsTo:                      # GDI standards this dataset claims \
                (list; optional)";
    format!(
        "{head}\n  #   Uncomment the ones that apply. The CLOSED set the node accepts:\n{}",
        rows.join("\n")
    )
}

/// The scaffolded `package.yaml` template.
///
/// Required fields are `REPLACE:` placeholders except `applicableLegislation`
/// (the EHDS ELI) and `license` (a `REPLACE:` placeholder). Recommended fields
/// are under their own header; optional fields are commented with examples.
///
/// `catalog_line` is the rendered `metadata.catalog` line (with any trailing
/// allow-list comment): either the static `REPLACE:` placeholder or, when the
/// active profile has a `catalogs` allow-list, the available catalog name(s)
/// (see [`scaffold_catalog_line`]).
#[expect(
    clippy::too_many_lines,
    reason = "all but a handful of these lines are ONE string literal — the scaffold document \
              this command writes. Splitting it to satisfy the line count would hide the shape \
              of the file a provider actually gets, which is the only thing this function is \
              for; the interpolated pieces are already extracted."
)]
fn template(catalog_line: &str) -> String {
    format!(
        r#"metadata:
  # --- Core identity (REQUIRED) ---
  # GOE or GDI prefix for the dataset ID (CC added from tool config, timestamp generated).
  prefix: "REPLACE: GOE or GDI"
  # Institute abbreviation for the dataset ID (e.g. UTARTU, DKFZ, HRI; max 16 [A-Z]).
  org: "REPLACE: ORG"
  # Catalog name; must match a catalog defined in the service config (max 64 chars).
  {catalog_line}
  # Dataset title; max 255 chars (supports an optional language map: {{en: "...", et: "..."}}).
  # Convention: include "allele frequency" and/or "synthetic data" in the title when applicable.
  title: "REPLACE: Dataset title"
  # Free-text description (supports an optional language map).
  description: "REPLACE: Dataset description"

  # --- Access, rights & legal (REQUIRED) ---
  # PUBLIC, RESTRICTED, or NON_PUBLIC (full EU authority IRI). Always explicit.
  accessRights: "REPLACE: http://publications.europa.eu/resource/authority/access-right/PUBLIC"
  # Legislation mandating the dataset (EU ELI IRIs, list; 1..n). Pre-filled with the EHDS ELI,
  # which health datasets are expected to cite; you MAY remove it: build/validate then WARN,
  # and under `--strict` that warning FAILS the build (--strict is opting into "every warning
  # fails"). Add the GDPR ELI below if the dataset discloses personal data, plus any national
  # act; each entry is a plain IRI (an ELI is the expected shape).
  #   GDPR: http://data.europa.eu/eli/reg/2016/679/oj
  applicableLegislation:
    - "{EHDS_ELI}"
  # Reuse license for THIS dataset (IRI). Per-dataset: e.g. aggregated data may be CC-BY while
  # synthetic data is CC0. Prefer the EU licence-authority IRIs: catalog harvesters resolve
  # them to display labels, which the creativecommons.org deed URLs do not serve
  # (e.g. http://publications.europa.eu/resource/authority/licence/CC_BY_4_0).
  license: "REPLACE: license IRI"

  # --- Agents (creator REQUIRED, one or more) ---
  # publisher and hdab are NOT here: they are node identity from the service [fairdp] config.
  creator:
    - name: "REPLACE: Creating organisation"

  # --- Health-specific (REQUIRED) ---
  # {health_categories}
  healthCategory:
    - "REPLACE: http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic"

  # --- Recommended fields ---
  # Optional in cardinality, but gdi-metadata marks them "recommended"; build/validate emit a
  # NON-FATAL warning if absent; they power userportal discovery. Fill them in when you can.
  keywords:                          # Tags for discovery (list; each max 64 chars, max 50)
    - allele-frequency
    - genomics
  # numberOfUniqueIndividuals: 1234  # DISTINCT sequenced subjects across the WHOLE dataset
  #                                  # (cohort size). Uncomment and set your REAL value:
  #                                  # `--strict` WARNS while it is absent (which nudges you
  #                                  # to fill it), whereas a literal 0 would silently
  #                                  # advertise a cohort of zero AND pass `--strict`.

  # --- Optional fields (uncomment and fill in as needed) ---
  # {conforms_to}
  # type: set ONLY for synthetic datasets; the single defined value is
  #   "https://publications.europa.eu/resource/authority/dataset-type/SYNTHETIC_DATA".
  # legalBasis:                      # DPV legal basis IRIs (list); for real personal data
  #   - "https://w3id.org/dpv#Consent"
  # isReferencedBy:                  # Publication DOI IRIs (list)
  #   - "https://doi.org/10.1234/example"
  # otherIdentifier:                 # Secondary identifiers (list)
  #   - notation: "DOI-12345"        # Required within identifier
  #     schemaAgency: "DataCite"     # Recommended within the identifier
  #     name: "Example identifier"   # Optional
  # contactPoint:                    # Dataset-level contact (fn and hasEmail required when present)
  #   fn: "Data team"
  #   hasEmail: "mailto:data@example.org"

files:
  # The dataset's content + provenance inventory. The first VCF group is REQUIRED and drives
  # parquet conversion. Paths can be relative (resolved against this YAML's directory) or absolute.
  # sha256/size are optional (computed if omitted, verified if provided).
  - category: "VCF"                  # Reserved (case-insensitive); drives parquet conversion
    reference: "REPLACE: GRCh38"     # Required for VCF: sets the dataset assembly
    # preciseReference: "GRCh38.p14" # Optional: patch-level provenance (not used for matching)
    files:
      - "REPLACE: path/to/your.vcf.gz"
  # - category: "BAM"                # Free string (recommended set); integrated-mode provenance only
  #   reference: "GRCh38"
  #   files:
  #     - "path/to/file.bam"

internal:
  # Non-public bookkeeping (node-opaque; stripped at ingest; tool<->backend only).
  # internalId: "EGV012346"          # Optional org-internal handle
  # pastVersion: "GDI-EE-UTARTU-20240601120000004"  # Optional; the single dataset this one supersedes

config:
  mode: aggregated                   # aggregated = allele frequencies (only mode implemented)
  blockRange: 10000000               # Position-based block range in bases (0 = single file per chr)
  # Allele-frequency provenance (aggregated datasets only): emitted as the beacon
  # frequencyInPopulations source/sourceReference. The values below are the standard
  # Genome of Europe pair: uncomment BOTH for a GoE (MAP stage 1) dataset, or replace
  # them with the cohort/study the AFs actually came from. Optional: when omitted,
  # the serving node falls back to its own beacon name + base URL.
  # afSource: "{GOE_AF_SOURCE}"
  # afSourceReference: "{GOE_AF_SOURCE_REFERENCE}"
  minAlleleCount: 0                  # BUILD-time AC floor (0 = off). Counts ALLELES,
                                     # not individuals: a homozygote adds 2, so use ~2*k
                                     # (10 for k=5 people). It bounds singleton
                                     # re-identification ONLY; no floor value prevents
                                     # multi-variant membership inference.
                                     # Rows below it are DROPPED from the package here and
                                     # cannot be recovered without a rebuild. This is NOT the
                                     # node's serve-time [beacon].min_allele_count; the two
                                     # compose as max(build, serve), so 0 is fine when the
                                     # node sets its own floor.
"#,
        health_categories = health_category_comment(),
        conforms_to = conforms_to_comment(),
    )
}

/// Run `init`: scaffold a `package.yaml` template, printing a success line.
///
/// Offline-only: the active profile's `catalogs` allow-list (if any) is used to
/// scaffold the `metadata.catalog` field; the network is never reached.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the output already exists without
/// `--force`, or if the file cannot be written. A missing/unloadable profile is
/// **not** fatal — `init` falls back to the static placeholder.
pub fn run(
    args: &InitArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let out = args.output.as_path();
    crate::output::note(&format!(
        "output package template: {} (force: {})",
        out.display(),
        args.force
    ));
    // Profile lookup is best-effort: any failure keeps the static placeholder so
    // `init` works without a profile (it must never require one or hit the network).
    let active = profile::load_active(config_path, profile_name).ok();
    let catalog_line = active.as_ref().map_or_else(
        || CATALOG_PLACEHOLDER.to_owned(),
        |p| scaffold_catalog_line(p.catalogs.keys().map(String::as_str)),
    );
    match active.as_ref() {
        Some(p) => crate::output::note(&format!(
            "scaffolding metadata.catalog from the active profile allow-list ({} catalog(s))",
            p.catalogs.len()
        )),
        None => crate::output::note(
            "no active profile; scaffolding metadata.catalog with the static REPLACE placeholder",
        ),
    }
    write_template(out, args.force, &catalog_line)?;
    crate::output::note(
        "wrote template: applicableLegislation pre-filled with the EHDS ELI (removable; \
         build warns, and `--strict` fails on that warning; add the GDPR or a national act \
         beside it); required fields left as REPLACE placeholders",
    );
    println!("wrote package template to {}", out.display());
    // First-run next-step nudge (stderr, so stdout stays the scriptable path line):
    // point the operator at editing the template and the build that consumes it.
    eprintln!(
        "next: edit {} (metadata + VCF file groups), then run \
         `gdi-dataset-tool build {} --cc <CC>` (the two-letter country code, or set \
         the `country_code` key / GDI_TOOL__COUNTRY_CODE so you can omit --cc)",
        out.display(),
        out.display()
    );
    Ok(())
}

/// Render the `metadata.catalog` line from the profile's allow-list names: the
/// first name becomes the value, any others are listed in a trailing comment. An
/// empty list yields the static `REPLACE:` placeholder.
fn scaffold_catalog_line<'a>(names: impl Iterator<Item = &'a str>) -> String {
    let names: Vec<&str> = names.collect();
    match names.split_first() {
        None => CATALOG_PLACEHOLDER.to_owned(),
        Some((first, [])) => format!(r#"catalog: "{first}""#),
        Some((first, rest)) => {
            format!(
                r#"catalog: "{first}"   # other allowed catalogs: {}"#,
                rest.join(", ")
            )
        }
    }
}

/// Write the scaffolded `package.yaml` template to `out`, with `catalog_line` as
/// the rendered `metadata.catalog` line.
///
/// Refuses to overwrite an existing file unless `force`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if `out` exists and `force` is false, or on
/// any filesystem error.
#[expect(
    clippy::disallowed_methods,
    reason = "scaffolds a config file for a human to edit; a torn file is regenerated"
)]
pub fn write_template(out: &Path, force: bool, catalog_line: &str) -> Result<(), ToolError> {
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
        fs::create_dir_all(parent)
            .map_err(|e| ToolError::user(format!("cannot create {}: {e}", parent.display())))?;
    }
    fs::write(out, template(catalog_line))
        .map_err(|e| ToolError::user(format!("cannot write {}: {e}", out.display())))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn template_carries_ehds_eli_and_replace_markers() {
        let body = template(CATALOG_PLACEHOLDER);
        assert!(body.contains(EHDS_ELI), "EHDS ELI must be pre-filled");
        assert!(
            body.contains("REPLACE:"),
            "required fields are placeholders"
        );
        // The four sections are present.
        assert!(body.contains("metadata:"));
        assert!(body.contains("files:"));
        assert!(body.contains("internal:"));
        assert!(body.contains("config:"));
        // The recommended-fields header stands out.
        assert!(body.contains("--- Recommended fields ---"));
        // The afSource example is the standard Genome of Europe pair (single-sourced
        // from `wizard::fields`, the same values the wizard offers) — commented out,
        // because the field is optional.
        assert!(body.contains(&format!("# afSource: \"{GOE_AF_SOURCE}\"")));
        assert!(body.contains(&format!(
            "# afSourceReference: \"{GOE_AF_SOURCE_REFERENCE}\""
        )));
    }

    #[test]
    fn write_refuses_existing_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("package.yaml");
        std::fs::write(&out, b"existing").unwrap();
        let err = write_template(&out, false, CATALOG_PLACEHOLDER).unwrap_err();
        assert_eq!(err.exit_code, 1);
        assert!(err.message.contains("already exists"));
        // --force overwrites.
        write_template(&out, true, CATALOG_PLACEHOLDER).unwrap();
        let body = std::fs::read_to_string(&out).unwrap();
        assert!(body.contains("metadata:"));
    }

    #[test]
    fn scaffold_catalog_line_renders_names() {
        // No names -> the static placeholder.
        assert_eq!(
            scaffold_catalog_line(std::iter::empty()),
            CATALOG_PLACEHOLDER
        );
        // One name -> it becomes the value.
        assert_eq!(
            scaffold_catalog_line(["gdi-aggregated"].into_iter()),
            r#"catalog: "gdi-aggregated""#
        );
        // Several names -> first is the value, the rest are listed in a comment.
        let line = scaffold_catalog_line(["a", "b", "c"].into_iter());
        assert!(line.starts_with(r#"catalog: "a""#), "got: {line}");
        assert!(line.contains("other allowed catalogs: b, c"), "got: {line}");
    }
}
