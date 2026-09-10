//! The static metadata->RDF mapping table — the in-repo encoding of the
//! gdi-metadata SHACL shape.
//!
//! Each row pairs a [`MetaField`] with the `predicate` IRI emitted on the dataset
//! record. Adding or removing a field is a one-line change here, diffable against
//! gdi-metadata. The graph builder ([`crate::graph`]) walks these entries; a per-field
//! arm there picks the `DatasetEntry` value and its RDF encoding (langString, typed
//! literal, IRI, blank node), so the encoding lives with the builder rather than in a
//! parallel column here.

use crate::vocab;

/// Which per-dataset metadata field an entry covers — the accessor the graph
/// builder switches on to pull the value(s) out of the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetaField {
    /// `datasetId` as a `dct:identifier` string literal (also the resource slug).
    Identifier,
    /// Localized `title`.
    Title,
    /// Localized `description`.
    Description,
    /// `accessRights` authority IRI.
    AccessRights,
    /// `applicableLegislation` ELI IRIs.
    ApplicableLegislation,
    /// `license` IRI.
    License,
    /// `creator` agents (blank nodes).
    Creator,
    /// `healthCategory` IRIs.
    HealthCategory,
    /// `keywords` string literals.
    Keyword,
    /// `numberOfUniqueIndividuals` (`xsd:nonNegativeInteger`).
    NumberOfUniqueIndividuals,
    /// `numberOfRecords` (`xsd:nonNegativeInteger`).
    NumberOfRecords,
    /// `conformsTo` GDI-standard IRIs.
    ConformsTo,
    /// `type` IRI (only for synthetic datasets).
    Type,
    /// `legalBasis` DPV IRIs.
    LegalBasis,
    /// `isReferencedBy` DOI IRIs.
    IsReferencedBy,
    /// `otherIdentifier` (nested `adms:Identifier` blank node).
    OtherIdentifier,
    /// dataset-level `contactPoint` (nested `vcard:Kind` blank node).
    ContactPoint,
    /// `dct:issued` (creation time, `xsd:dateTime`).
    Issued,
    /// `dct:modified` (creation time while immutable, `xsd:dateTime`).
    Modified,
    /// `dcat:theme` (node-config concept IRIs).
    Theme,
    /// `dct:language` (the node-config authority IRI).
    Language,
    /// `dct:publisher` (node-config `foaf:Agent` blank node, card. 1).
    Publisher,
    /// `healthdcatap:hdab` (node-config `foaf:Agent` blank node).
    Hdab,
    /// `dcat:distribution` (the generated distribution IRI).
    Distribution,
    /// `adms:status` (the constant `COMPLETED` authority IRI).
    Status,
}

/// One row of the static mapping table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FieldMapping {
    /// The field this row covers.
    pub field: MetaField,
    /// The predicate IRI emitted on the dataset record.
    pub predicate: &'static str,
}

/// The Dataset record's static mapping table — the gdi-metadata `DatasetShape`
/// encoded as data.
///
/// The graph builder iterates this in order; the per-field accessor it switches on owns
/// the source (per-dataset, node-config or generated) and the RDF encoding.
/// `otherIdentifier` needs its own row because it renders as a nested blank node.
pub(crate) const DATASET_MAPPING: &[FieldMapping] = &[
    FieldMapping {
        field: MetaField::Identifier,
        predicate: vocab::DCT_IDENTIFIER,
    },
    FieldMapping {
        field: MetaField::Title,
        predicate: vocab::DCT_TITLE,
    },
    FieldMapping {
        field: MetaField::Description,
        predicate: vocab::DCT_DESCRIPTION,
    },
    FieldMapping {
        field: MetaField::AccessRights,
        predicate: vocab::DCT_ACCESS_RIGHTS,
    },
    FieldMapping {
        field: MetaField::ApplicableLegislation,
        predicate: vocab::DCATAP_APPLICABLE_LEGISLATION,
    },
    FieldMapping {
        field: MetaField::License,
        predicate: vocab::DCT_LICENSE,
    },
    FieldMapping {
        field: MetaField::Creator,
        predicate: vocab::DCT_CREATOR,
    },
    FieldMapping {
        field: MetaField::Publisher,
        predicate: vocab::DCT_PUBLISHER,
    },
    FieldMapping {
        field: MetaField::Hdab,
        predicate: vocab::HEALTHDCATAP_HDAB,
    },
    FieldMapping {
        field: MetaField::HealthCategory,
        predicate: vocab::HEALTHDCATAP_HEALTH_CATEGORY,
    },
    FieldMapping {
        field: MetaField::Keyword,
        predicate: vocab::DCAT_KEYWORD,
    },
    FieldMapping {
        field: MetaField::NumberOfUniqueIndividuals,
        predicate: vocab::HEALTHDCATAP_NUMBER_OF_UNIQUE_INDIVIDUALS,
    },
    FieldMapping {
        field: MetaField::NumberOfRecords,
        predicate: vocab::HEALTHDCATAP_NUMBER_OF_RECORDS,
    },
    FieldMapping {
        field: MetaField::ConformsTo,
        predicate: vocab::DCT_CONFORMS_TO,
    },
    FieldMapping {
        field: MetaField::Type,
        predicate: vocab::DCT_TYPE,
    },
    FieldMapping {
        field: MetaField::LegalBasis,
        predicate: vocab::DPV_HAS_LEGAL_BASIS,
    },
    FieldMapping {
        field: MetaField::IsReferencedBy,
        predicate: vocab::DCT_IS_REFERENCED_BY,
    },
    FieldMapping {
        field: MetaField::OtherIdentifier,
        predicate: vocab::ADMS_IDENTIFIER,
    },
    FieldMapping {
        field: MetaField::ContactPoint,
        predicate: vocab::DCAT_CONTACT_POINT,
    },
    FieldMapping {
        field: MetaField::Theme,
        predicate: vocab::DCAT_THEME,
    },
    FieldMapping {
        field: MetaField::Language,
        predicate: vocab::DCT_LANGUAGE,
    },
    FieldMapping {
        field: MetaField::Issued,
        predicate: vocab::DCT_ISSUED,
    },
    FieldMapping {
        field: MetaField::Modified,
        predicate: vocab::DCT_MODIFIED,
    },
    FieldMapping {
        field: MetaField::Distribution,
        predicate: vocab::DCAT_DISTRIBUTION_PRED,
    },
    FieldMapping {
        field: MetaField::Status,
        predicate: vocab::ADMS_STATUS,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `MetaField` must have a row in `DATASET_MAPPING`.
    ///
    /// The graph builder iterates the table and switches on each row's field, so a variant
    /// with no row is never reached and its property is silently absent from every dataset
    /// record. The exhaustive match in `graph.rs` proves every field can be rendered, not
    /// that any row asks for it.
    #[test]
    fn every_meta_field_has_a_row_in_the_dataset_mapping() {
        const ALL: &[MetaField] = &[
            MetaField::Identifier,
            MetaField::Title,
            MetaField::Description,
            MetaField::AccessRights,
            MetaField::ApplicableLegislation,
            MetaField::License,
            MetaField::Creator,
            MetaField::HealthCategory,
            MetaField::Keyword,
            MetaField::NumberOfUniqueIndividuals,
            MetaField::NumberOfRecords,
            MetaField::ConformsTo,
            MetaField::Type,
            MetaField::LegalBasis,
            MetaField::IsReferencedBy,
            MetaField::OtherIdentifier,
            MetaField::ContactPoint,
            MetaField::Issued,
            MetaField::Modified,
            MetaField::Theme,
            MetaField::Language,
            MetaField::Publisher,
            MetaField::Hdab,
            MetaField::Distribution,
            MetaField::Status,
        ];

        // Compile tripwire: naming every variant means a new one fails to build here,
        // which brings its author to the assertions below.
        for f in ALL {
            match f {
                MetaField::Identifier
                | MetaField::Title
                | MetaField::Description
                | MetaField::AccessRights
                | MetaField::ApplicableLegislation
                | MetaField::License
                | MetaField::Creator
                | MetaField::HealthCategory
                | MetaField::Keyword
                | MetaField::NumberOfUniqueIndividuals
                | MetaField::NumberOfRecords
                | MetaField::ConformsTo
                | MetaField::Type
                | MetaField::LegalBasis
                | MetaField::IsReferencedBy
                | MetaField::OtherIdentifier
                | MetaField::ContactPoint
                | MetaField::Issued
                | MetaField::Modified
                | MetaField::Theme
                | MetaField::Language
                | MetaField::Publisher
                | MetaField::Hdab
                | MetaField::Distribution
                | MetaField::Status => {}
            }
        }

        for f in ALL {
            assert!(
                DATASET_MAPPING.iter().any(|m| m.field == *f),
                "{f:?} has no DATASET_MAPPING row, so the graph builder never emits it — the \
                     property is silently absent from every dataset record"
            );
        }

        // And no orphan rows: a row whose field is not in `all` means this guard has fallen
        // behind the enum and is checking less than it claims.
        for m in DATASET_MAPPING {
            assert!(
                ALL.contains(&m.field),
                "{:?} has a mapping row but is missing from this guard's list",
                m.field
            );
        }

        // The other direction: a new field on the source struct with no `MetaField`
        // variant. `core::model`'s own exhaustive destructures stop at the crate boundary,
        // and the golden snapshot can only see a field that is rendered, never one that is
        // missing. The destructure below stops this build until a new `ManifestMetadata`
        // field is either mapped or named as unpublished.
        assert_every_manifest_metadata_field_is_considered();
    }

    /// Compile-time tripwire: adding a field to `ManifestMetadata` stops this build until
    /// it is either mapped to a [`MetaField`] or named as unpublished.
    ///
    /// Takes a reference rather than constructing a value: the struct has no `Default`.
    fn assert_every_manifest_metadata_field_is_considered() {
        fn destructure(m: &gdi_node_standalone_core::model::manifest::ManifestMetadata) {
            let gdi_node_standalone_core::model::manifest::ManifestMetadata {
                // Structural, not DCAT properties: the id becomes the subject IRI and the
                // catalog the containment edge, so neither is a mapped predicate.
                dataset_id: _,
                catalog: _,
                // Each of these has a `MetaField` row asserted above.
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
                number_of_records: _,
                // Not published: the population breakdown is beacon query surface,
                // re-derived at ingest and disclosure-gated at serve time. It has no DCAT
                // predicate and must not acquire one.
                populations: _,
            } = m;
        }
        // Referencing it is what forces the body to type-check.
        let _ = destructure;
    }

    #[test]
    fn dataset_mapping_carries_identifier_row() {
        let identifier = DATASET_MAPPING
            .iter()
            .find(|m| m.field == MetaField::Identifier)
            .expect("the table always carries the identifier row");
        assert_eq!(identifier.predicate, "http://purl.org/dc/terms/identifier");
    }
}
