//! `check` consistency logic: assert the running service's FDP dataset output
//! matches the package's public metadata.
//!
//! The tool fetches the dataset's FDP record (`{service_url}/fairdp/dataset/{id}`),
//! reads the package's `manifest.json` (the FDP-public `metadata` section), and
//! asserts the key public values the FDP renders from that metadata are present in
//! the served graph: the dataset id (as the resource IRI slug and the `dct:identifier`
//! literal), the title literal, the license IRI, and the access-rights IRI. A missing
//! value is a reported mismatch, not a crash, so `check` surfaces a drift between what
//! was packaged and what the node serves.
//!
//! The comparison keys on stable IRI/literal substrings rather than a full RDF
//! parse (no new deps; robust to Turtle/JSON-LD formatting). Each routine is a
//! CLI-independent library function; `cmd_check` is the wrapper.

use gdi_node_standalone_core::model::manifest::ManifestMetadata;
use gdi_node_standalone_core::model::metadata::LocalizedText;

/// One field-level consistency check between the package and the FDP output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FieldCheck {
    /// The field name (e.g. `datasetId`, `title`, `license`).
    pub field: String,
    /// The value expected from the package manifest.
    pub expected: String,
    /// Whether the value was found in the served FDP graph.
    pub ok: bool,
}

/// The outcome of checking one dataset: the per-field results.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CheckReport {
    /// The dataset id checked.
    pub id: String,
    /// The per-field consistency results.
    pub fields: Vec<FieldCheck>,
    /// Why the node did not serve this dataset, when it did not.
    ///
    /// Carried as an outcome rather than propagated as an error: `--all` selects hidden ids
    /// too (`upload` deposits hidden by default) and the node serves `/fairdp/dataset/{id}`
    /// only for a visible dataset, so a normal bucket structurally contains ids that 404.
    /// Aborting on the first would discard every prior result and suppress the JSON
    /// envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<String>,
}

impl CheckReport {
    /// Whether every checked field matched.
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.unavailable.is_none() && self.fields.iter().all(|f| f.ok)
    }
}

/// Render a [`LocalizedText`] to its primary string for substring comparison
/// (a plain string, or the first language value of a map).
fn localized_to_string(text: &LocalizedText) -> Option<String> {
    match text {
        LocalizedText::Plain(s) => Some(s.clone()),
        LocalizedText::Map(m) => m.values().next().cloned(),
    }
}

/// One "is this manifest value present in the served graph?" check: `value` is what the
/// FDP should render from the manifest, and it must appear verbatim in `body`. Building
/// the check here keeps the reported `expected` and the searched substring the same
/// value, rather than repeating that pairing per field.
fn present(field: &str, value: &str, body: &str) -> FieldCheck {
    FieldCheck {
        field: field.to_owned(),
        expected: value.to_owned(),
        ok: body.contains(value),
    }
}

/// Compare a package's `metadata` against a served FDP dataset graph `body`,
/// returning the per-field [`CheckReport`].
///
/// Asserts each key public value the FDP renders from the manifest is present in
/// the served graph: the `datasetId` (the resource IRI slug or the `dct:identifier`
/// literal), the `title`, the `license` IRI, and the `accessRights` IRI.
#[must_use]
pub fn check_against_fdp(metadata: &ManifestMetadata, body: &str) -> CheckReport {
    // datasetId: present as the IRI slug or a string literal.
    let mut fields = vec![present("datasetId", &metadata.dataset_id, body)];
    // title: the localized title literal (only when the manifest carries one).
    if let Some(title) = localized_to_string(&metadata.title) {
        fields.push(present("title", &title, body));
    }
    // license: the license IRI; accessRights: the access-rights authority IRI.
    fields.push(present("license", &metadata.license, body));
    fields.push(present("accessRights", &metadata.access_rights, body));

    CheckReport {
        id: metadata.dataset_id.clone(),
        fields,
        unavailable: None,
    }
}

#[cfg(test)]
mod unavailable_tests {
    use super::*;

    /// A dataset the node did not serve must be a reported outcome, not an aborted run:
    /// propagating it would leave the remaining ids unchecked, discard the passing
    /// results, and suppress the `{"schemaVersion":1,"results":[…]}` envelope.
    #[test]
    fn an_unavailable_dataset_is_not_ok_but_is_still_a_report() {
        let report = CheckReport {
            id: "GDI-EE-UTARTU-20260409143052837".to_owned(),
            fields: Vec::new(),
            unavailable: Some("FDP returned 404".to_owned()),
        };
        assert!(
            !report.all_ok(),
            "an unserved dataset must count as a mismatch, not silently pass on zero fields"
        );
    }

    /// The complement: with no fields and no unavailability there is nothing wrong.
    #[test]
    fn a_report_with_no_findings_is_ok() {
        let report = CheckReport {
            id: "GDI-EE-UTARTU-20260409143052837".to_owned(),
            fields: Vec::new(),
            unavailable: None,
        };
        assert!(report.all_ok());
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use gdi_node_standalone_core::model::metadata::Agent;

    use super::*;

    fn metadata() -> ManifestMetadata {
        ManifestMetadata {
            dataset_id: "GDI-EE-UTARTU-20260409143052837".to_owned(),
            catalog: "synthetic-data".to_owned(),
            title: LocalizedText::Plain("Synthetic AF dataset".to_owned()),
            description: None,
            access_rights: "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
                .to_owned(),
            applicable_legislation: vec!["http://data.europa.eu/eli/reg/2025/327/oj".to_owned()],
            license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
            creator: vec![Agent {
                name: "University of Tartu".to_owned(),
            }],
            health_category: vec!["http://example/cat".to_owned()],
            keywords: None,
            number_of_unique_individuals: None,
            conforms_to: None,
            type_: None,
            legal_basis: None,
            is_referenced_by: None,
            other_identifier: None,
            contact_point: None,
            number_of_records: None,
            populations: None,
        }
    }

    fn matching_graph(m: &ManifestMetadata) -> String {
        format!(
            r#"<https://n/fairdp/dataset/{id}> a dcat:Dataset ;
  dct:identifier "{id}"^^xsd:string ;
  dct:title "Synthetic AF dataset" ;
  dct:license <{license}> ;
  dct:accessRights <{ar}> ."#,
            id = m.dataset_id,
            license = m.license,
            ar = m.access_rights,
        )
    }

    #[test]
    fn matching_graph_passes_all_fields() {
        let m = metadata();
        let report = check_against_fdp(&m, &matching_graph(&m));
        assert!(report.all_ok(), "{report:?}");
        assert_eq!(report.fields.len(), 4);
    }

    #[test]
    fn mismatched_title_is_reported() {
        let m = metadata();
        // A graph with the wrong title.
        let body = matching_graph(&m).replace("Synthetic AF dataset", "WRONG TITLE");
        let report = check_against_fdp(&m, &body);
        assert!(!report.all_ok());
        let title = report.fields.iter().find(|f| f.field == "title").unwrap();
        assert!(!title.ok);
        // The other fields still match.
        assert!(
            report
                .fields
                .iter()
                .find(|f| f.field == "license")
                .unwrap()
                .ok
        );
    }

    #[test]
    fn missing_license_is_reported() {
        let m = metadata();
        let body = matching_graph(&m).replace(&m.license, "https://other.example/license");
        let report = check_against_fdp(&m, &body);
        assert!(!report.all_ok());
        assert!(
            !report
                .fields
                .iter()
                .find(|f| f.field == "license")
                .unwrap()
                .ok
        );
    }

    // A `LocalizedText::Map` renders as its first value in lexicographic key order, so
    // the selection is deterministic rather than insertion-ordered: "en" < "et" < "fi".
    #[test]
    fn localized_to_string_map_returns_first_btreemap_value() {
        use std::collections::BTreeMap;
        let mut m = BTreeMap::new();
        m.insert("fi".to_owned(), "Finnish title".to_owned());
        m.insert("en".to_owned(), "English title".to_owned());
        m.insert("et".to_owned(), "Estonian title".to_owned());
        let text = LocalizedText::Map(m);
        let result = localized_to_string(&text);
        assert_eq!(result.as_deref(), Some("English title"));
    }
}
