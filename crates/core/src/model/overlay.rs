//! The operator metadata overlay: a field patch over a dataset's published `metadata`
//! section. `deny_unknown_fields` makes the struct itself the editable allow-list:
//! `datasetId`, `catalog`, `numberOfRecords`, `populations` and any unknown key fail to
//! parse, so they can never be edited. See [`crate::overlay_store`] for how a patch is
//! applied.

use serde::{Deserialize, Serialize};

use super::manifest::ManifestMetadata;
use super::metadata::{Agent, ContactPoint, LocalizedText, OtherIdentifier};
use super::package::PackageMetadata;

/// A patch over a dataset's FDP-served metadata. Every field is optional: a field present
/// in the JSON overwrites the baseline, an absent field is left untouched. Clearing a field
/// back to absent is not supported. Re-edit with the desired value instead.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetadataOverlay {
    /// Dataset title (plain string or language map).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<LocalizedText>,
    /// Free-text description (plain string or language map).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<LocalizedText>,
    /// Access rights authority IRI (`PUBLIC` / `RESTRICTED` / `NON_PUBLIC`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_rights: Option<String>,
    /// Legislation mandating the dataset (EU ELI IRIs, >= 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applicable_legislation: Option<Vec<String>>,
    /// Reuse license for this dataset (IRI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Creating agents (>= 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<Vec<Agent>>,
    /// GDI health category IRIs (>= 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_category: Option<Vec<String>>,
    /// Tags for discovery (recommended).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keywords: Option<Vec<String>>,
    /// Distinct sequenced subjects across the whole dataset (recommended).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number_of_unique_individuals: Option<u64>,
    /// Standards-compliance IRIs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conforms_to: Option<Vec<String>>,
    /// Dataset type IRI, set only for synthetic datasets.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    /// DPV legal basis IRIs (for real personal data).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_basis: Option<Vec<String>>,
    /// Publication DOI IRIs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_referenced_by: Option<Vec<String>>,
    /// Secondary identifiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_identifier: Option<Vec<OtherIdentifier>>,
    /// Dataset-level contact point.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_point: Option<ContactPoint>,
}

impl MetadataOverlay {
    /// True when the patch sets no fields (a no-op overlay).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl ManifestMetadata {
    /// A validation view of this served metadata as the provider-input
    /// [`PackageMetadata`] shape, dropping the build-generated `dataset_id` /
    /// `number_of_records` (not part of the editable surface) and the legacy
    /// `prefix`/`org`. Used to re-run the gdi-metadata field validators over a
    /// merged overlay result.
    #[must_use]
    pub fn as_package_metadata(&self) -> PackageMetadata {
        PackageMetadata {
            prefix: None,
            org: None,
            catalog: self.catalog.clone(),
            title: self.title.clone(),
            description: self.description.clone(),
            access_rights: self.access_rights.clone(),
            applicable_legislation: self.applicable_legislation.clone(),
            license: self.license.clone(),
            creator: self.creator.clone(),
            health_category: self.health_category.clone(),
            keywords: self.keywords.clone(),
            number_of_unique_individuals: self.number_of_unique_individuals,
            conforms_to: self.conforms_to.clone(),
            type_: self.type_.clone(),
            legal_basis: self.legal_basis.clone(),
            is_referenced_by: self.is_referenced_by.clone(),
            other_identifier: self.other_identifier.clone(),
            contact_point: self.contact_point.clone(),
        }
    }

    /// Apply an operator overlay: each `Some` field in `ov` overwrites this
    /// metadata's corresponding field. Protected fields (`dataset_id`, `catalog`,
    /// `number_of_records`) are absent from [`MetadataOverlay`] and so are never
    /// touched.
    pub fn apply_overlay(&mut self, ov: &MetadataOverlay) {
        // Exhaustiveness guard in both directions. Neither destructure below uses a `..`
        // rest pattern, so a field added to `ManifestMetadata` or to `MetadataOverlay`
        // fails to compile here until it is named. Without the manifest side, a new DCAT
        // field could be added to the served metadata and never offered to the overlay,
        // leaving it permanently un-correctable by any operator command.
        //
        // Naming a field is not applying it: the compiler does not force the matching
        // `if let Some(v) = &ov.field` branch below. The test that binds that is
        // `every_overlay_field_is_actually_applied` in this file's `mod tests`, which
        // applies every overlay field and asserts each one lands.
        let ManifestMetadata {
            // Protected: not patchable by an operator overlay. `deny_unknown_fields` on
            // `MetadataOverlay` rejects these keys at parse time; listing them here makes
            // that a decision rather than an omission.
            dataset_id: _,
            catalog: _,
            number_of_records: _,
            populations: _,
            // Patchable: each has a matching `MetadataOverlay` field applied below.
            title: _,
            description: _,
            access_rights: _,
            applicable_legislation: _,
            license: _,
            creator: _,
            health_category: _,
            keywords: _,
            number_of_unique_individuals: _,
            conforms_to: _,
            type_: _,
            legal_basis: _,
            is_referenced_by: _,
            other_identifier: _,
            contact_point: _,
        } = self;

        let MetadataOverlay {
            title: _,
            description: _,
            access_rights: _,
            applicable_legislation: _,
            license: _,
            creator: _,
            health_category: _,
            keywords: _,
            number_of_unique_individuals: _,
            conforms_to: _,
            type_: _,
            legal_basis: _,
            is_referenced_by: _,
            other_identifier: _,
            contact_point: _,
        } = ov;

        if let Some(v) = &ov.title {
            self.title.clone_from(v);
        }
        if let Some(v) = &ov.description {
            self.description = Some(v.clone());
        }
        if let Some(v) = &ov.access_rights {
            self.access_rights.clone_from(v);
        }
        if let Some(v) = &ov.applicable_legislation {
            self.applicable_legislation.clone_from(v);
        }
        if let Some(v) = &ov.license {
            self.license.clone_from(v);
        }
        if let Some(v) = &ov.creator {
            self.creator.clone_from(v);
        }
        if let Some(v) = &ov.health_category {
            self.health_category.clone_from(v);
        }
        if let Some(v) = &ov.keywords {
            self.keywords = Some(v.clone());
        }
        if let Some(v) = ov.number_of_unique_individuals {
            self.number_of_unique_individuals = Some(v);
        }
        if let Some(v) = &ov.conforms_to {
            self.conforms_to = Some(v.clone());
        }
        if let Some(v) = &ov.type_ {
            self.type_ = Some(v.clone());
        }
        if let Some(v) = &ov.legal_basis {
            self.legal_basis = Some(v.clone());
        }
        if let Some(v) = &ov.is_referenced_by {
            self.is_referenced_by = Some(v.clone());
        }
        if let Some(v) = &ov.other_identifier {
            self.other_identifier = Some(v.clone());
        }
        if let Some(v) = &ov.contact_point {
            self.contact_point = Some(v.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap permitted in tests")]
    use super::*;
    use crate::model::{Agent, LocalizedText, ManifestMetadata};

    fn baseline() -> ManifestMetadata {
        ManifestMetadata {
            dataset_id: "GDI-EE-UTARTU-20260409143052837".to_owned(),
            catalog: "gdi-aggregated".to_owned(),
            title: LocalizedText::Plain("Old titel".to_owned()),
            description: None,
            access_rights: "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
                .to_owned(),
            applicable_legislation: vec!["http://data.europa.eu/eli/reg/2018/1725/oj".to_owned()],
            license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
            creator: vec![Agent {
                name: "University of Tartu".to_owned(),
            }],
            health_category: vec![
                "http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic".to_owned(),
            ],
            keywords: None,
            number_of_unique_individuals: None,
            conforms_to: None,
            type_: None,
            legal_basis: None,
            is_referenced_by: None,
            other_identifier: None,
            contact_point: None,
            number_of_records: Some(42),
            populations: None,
        }
    }

    #[test]
    fn every_overlay_field_is_actually_applied() {
        // What `apply_overlay`'s destructure cannot bind: that guard forces a new field to
        // be named in both patterns, not to be applied. A field that is named but never
        // assigned parses, validates, writes a durable override and reports success without
        // ever reaching the served metadata.
        //
        // The fields come from the overlay's own serialized form, so a field added later is
        // covered without editing this test. Every key the overlay carries must appear,
        // with that value, on the patched manifest.
        let overlay_json = serde_json::json!({
            "title": "T",
            "description": "D",
            "accessRights": "http://publications.europa.eu/resource/authority/access-right/RESTRICTED",
            "applicableLegislation": ["http://data.europa.eu/eli/reg/2025/327/oj"],
            "license": "https://example.org/lic",
            "creator": [{"name": "C"}],
            "healthCategory": ["http://example.org/hc"],
            "keywords": ["k"],
            "numberOfUniqueIndividuals": 7,
            "conformsTo": ["http://example.org/profile"],
            "type": "http://example.org/type",
            "legalBasis": ["http://example.org/lb"],
            "isReferencedBy": ["http://example.org/ref"],
            "otherIdentifier": [{"notation": "DOI:10.x"}],
            "contactPoint": {"fn": "N", "hasEmail": "mailto:a@b.co"}
        });
        let ov: MetadataOverlay =
            serde_json::from_value(overlay_json).expect("fixture must deserialize");

        // Anti-vacuity, compiler-bound. Destructuring makes a field added to the type a
        // compile error here, and the loop below names any field the fixture leaves unset.
        // Comparing the serialized overlay's key count against the fixture's cannot do
        // either: every field is `skip_serializing_if = "Option::is_none"`, so a field
        // missing from the fixture shrinks both sides together.
        let MetadataOverlay {
            title,
            description,
            access_rights,
            applicable_legislation,
            license,
            creator,
            health_category,
            keywords,
            number_of_unique_individuals,
            conforms_to,
            type_,
            legal_basis,
            is_referenced_by,
            other_identifier,
            contact_point,
        } = &ov;
        for (field, is_set) in [
            ("title", title.is_some()),
            ("description", description.is_some()),
            ("accessRights", access_rights.is_some()),
            ("applicableLegislation", applicable_legislation.is_some()),
            ("license", license.is_some()),
            ("creator", creator.is_some()),
            ("healthCategory", health_category.is_some()),
            ("keywords", keywords.is_some()),
            (
                "numberOfUniqueIndividuals",
                number_of_unique_individuals.is_some(),
            ),
            ("conformsTo", conforms_to.is_some()),
            ("type", type_.is_some()),
            ("legalBasis", legal_basis.is_some()),
            ("isReferencedBy", is_referenced_by.is_some()),
            ("otherIdentifier", other_identifier.is_some()),
            ("contactPoint", contact_point.is_some()),
        ] {
            assert!(
                is_set,
                "the fixture above does not set `{field}`, so the round-trip below never \
                 checks that `apply_overlay` applies it"
            );
        }

        let ov_map = serde_json::to_value(&ov)
            .expect("overlay serializes")
            .as_object()
            .expect("overlay is an object")
            .clone();

        let mut m = baseline();
        m.apply_overlay(&ov);
        let after = serde_json::to_value(&m).expect("manifest serializes");

        for (key, want) in &ov_map {
            let got = after.get(key).unwrap_or_else(|| {
                panic!("overlay field {key:?} has no counterpart on the patched manifest")
            });
            assert_eq!(
                got, want,
                "overlay field {key:?} was not applied: apply_overlay names it in the \
                 destructure but never assigns it, so the correction silently no-ops"
            );
        }
    }

    #[test]
    fn patch_overwrites_only_present_fields() {
        let mut m = baseline();
        let ov: MetadataOverlay =
            serde_json::from_str(r#"{"title":"Corrected title","keywords":["covid"]}"#).unwrap();
        m.apply_overlay(&ov);
        assert_eq!(m.title, LocalizedText::Plain("Corrected title".to_owned()));
        assert_eq!(m.keywords, Some(vec!["covid".to_owned()]));
        // untouched fields keep baseline; protected fields are unchanged.
        assert_eq!(m.license, "https://creativecommons.org/licenses/by/4.0/");
        assert_eq!(m.number_of_records, Some(42));
        assert_eq!(m.catalog, "gdi-aggregated");
    }

    #[test]
    fn unknown_or_protected_keys_are_rejected_at_parse() {
        for bad in [
            r#"{"datasetId":"GDI-EE-UTARTU-1"}"#,
            r#"{"catalog":"other"}"#,
            r#"{"numberOfRecords":7}"#,
            r#"{"somethingElse":true}"#,
        ] {
            let r: Result<MetadataOverlay, _> = serde_json::from_str(bad);
            assert!(r.is_err(), "must reject {bad}");
        }
    }

    #[test]
    fn localized_field_replaces_whole_value() {
        let mut m = baseline();
        let ov: MetadataOverlay =
            serde_json::from_str(r#"{"title":{"en":"Title","fi":"Otsikko"}}"#).unwrap();
        m.apply_overlay(&ov);
        match m.title {
            LocalizedText::Map(map) => {
                assert_eq!(map.get("en").unwrap(), "Title");
                assert_eq!(map.get("fi").unwrap(), "Otsikko");
            }
            LocalizedText::Plain(other) => panic!("expected map, got Plain({other:?})"),
        }
    }
}
