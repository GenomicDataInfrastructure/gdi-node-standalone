//! Golden + unit tests for the `datasets` entry type's `beaconCollectionsResponse`
//! assembly (`query::datasets_response`).
//!
//! The golden test renders the `beaconCollectionsResponse` nesting over a few visible
//! datasets: `meta` naming the `dataset` schema with the applied pagination,
//! `responseSummary`, and `response.collections[].{id,name,description?}`. The unit tests
//! pin the pagination contract: `numTotalResults` stays the true visible count while
//! `collections[]` is the page slice, and `limit:0` is clamped to `max_page_limit`, as on
//! `g_variants`.

use std::collections::BTreeMap;

use gdi_node_standalone_beacon::model::Pagination;
use gdi_node_standalone_beacon::query::datasets_response;
use gdi_node_standalone_beacon::request::apply_pagination;
use gdi_node_standalone_core::cache::DatasetEntry;
use gdi_node_standalone_core::model::{
    Assembly, DatasetMode, LocalizedText, ManifestConfig, ManifestMetadata,
};
use gdi_node_standalone_core::state::DatasetState;

/// A minimal `ManifestConfig`; only assembly and blockRange matter for the cache.
fn config() -> ManifestConfig {
    ManifestConfig {
        mode: DatasetMode::Aggregated,
        block_range: 10_000_000,
        af_source: None,
        af_source_reference: None,
        min_allele_count: 0,
        hide_lower_counts: None,
        assembly: Assembly {
            reference: "GRCh38".to_owned(),
        },
        manifest_version: 1,
        generated_by: "gdi-dataset-tool/test".to_owned(),
    }
}

/// A visible `DatasetEntry` with the given id, title and optional description.
fn entry(id: &str, title: LocalizedText, description: Option<LocalizedText>) -> DatasetEntry {
    DatasetEntry {
        id: id.to_owned(),
        metadata: ManifestMetadata {
            dataset_id: id.to_owned(),
            catalog: "gdi-aggregated".to_owned(),
            title,
            description,
            access_rights: "PUBLIC".to_owned(),
            applicable_legislation: vec![],
            license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
            creator: vec![],
            health_category: vec![],
            keywords: None,
            number_of_unique_individuals: None,
            conforms_to: None,
            type_: None,
            legal_basis: None,
            is_referenced_by: None,
            other_identifier: None,
            contact_point: None,
            number_of_records: Some(1),
            populations: None,
        },
        config: config(),
        state: DatasetState::Visible,
        metadata_modified: None,
    }
}

/// Three representative visible datasets: a plain title with a description, a plain title
/// with no description, and an `en`-keyed language-map title.
fn three_datasets() -> Vec<DatasetEntry> {
    let mut lang_title = BTreeMap::new();
    lang_title.insert("en".to_owned(), "Genome of Estonia".to_owned());
    lang_title.insert("et".to_owned(), "Eesti genoom".to_owned());
    // The first dataset carries a population set and a floor, so the golden snapshot pins
    // the `gdiDatasetInfo` wire contract an aggregator reads. The others leave
    // `populations` unset, pinning that the key is omitted rather than rendered empty.
    let mut first = entry(
        "GDI-EE-UTARTU-20260409143052837",
        LocalizedText::Plain("COVID monogenic AFs".to_owned()),
        Some(LocalizedText::Plain(
            "Aggregated allele frequencies for the COVID monogenic panel.".to_owned(),
        )),
    );
    first.metadata.populations = Some(vec!["EE".to_owned(), "FI".to_owned(), "Total".to_owned()]);
    first.config.min_allele_count = 5;
    vec![
        first,
        entry(
            "GDI-EE-UTARTU-20260411093000123",
            LocalizedText::Plain("Cardio panel AFs".to_owned()),
            None,
        ),
        entry(
            "GDI-EE-TUK-20260412120000000",
            LocalizedText::Map(lang_title),
            None,
        ),
    ]
}

#[test]
fn datasets_response_golden_snapshot() {
    let datasets = three_datasets();
    let refs: Vec<&DatasetEntry> = datasets.iter().collect();
    let resp = datasets_response(
        &refs,
        &Pagination::new(0, 10),
        &crate::fixtures::beacon_cfg(),
    );

    // One collection per visible dataset, the true total count, and exists.
    assert_eq!(resp.response.collections.len(), 3);
    assert_eq!(resp.response_summary.num_total_results, Some(3));
    assert!(resp.response_summary.exists);
    // id == datasetId, name == representative title literal.
    assert_eq!(
        resp.response.collections[0].id,
        "GDI-EE-UTARTU-20260409143052837"
    );
    assert_eq!(resp.response.collections[0].name, "COVID monogenic AFs");
    // A language-map title resolves to its `en` literal.
    assert_eq!(resp.response.collections[2].name, "Genome of Estonia");
    // create and update times are derived from the id's timestamp tail, matching the FDP
    // dct:issued and dct:modified, so they are present for a timestamped id.
    assert_eq!(
        resp.response.collections[0].create_date_time.as_deref(),
        Some("2026-04-09T14:30:52.837Z")
    );
    assert_eq!(
        resp.response.collections[0].update_date_time.as_deref(),
        Some("2026-04-09T14:30:52.837Z")
    );
    // The meta names the `dataset` schema rather than genomicVariant.
    assert_eq!(resp.meta.returned_schemas[0].entry_type, "dataset");

    insta::assert_json_snapshot!(resp);
}

#[test]
fn pagination_keeps_true_count_but_pages_collections() {
    let datasets = three_datasets();
    let refs: Vec<&DatasetEntry> = datasets.iter().collect();

    // skip 1, limit 1 -> one collection (the second dataset), true total stays 3.
    let resp = datasets_response(
        &refs,
        &Pagination::new(1, 1),
        &crate::fixtures::beacon_cfg(),
    );
    assert_eq!(resp.response_summary.num_total_results, Some(3));
    assert!(resp.response_summary.exists);
    assert_eq!(resp.response.collections.len(), 1);
    assert_eq!(
        resp.response.collections[0].id,
        "GDI-EE-UTARTU-20260411093000123"
    );
    // The applied pagination is echoed in the meta exactly.
    assert_eq!(resp.meta.received_request_summary.pagination.skip, 1);
    assert_eq!(resp.meta.received_request_summary.pagination.limit, 1);
}

#[test]
fn limit_zero_clamped_to_max_page_limit() {
    let cfg = crate::fixtures::beacon_cfg(); // default_page_limit 10, max_page_limit 1000
    let datasets = three_datasets();
    let refs: Vec<&DatasetEntry> = datasets.iter().collect();

    // Beacon's unbounded limit:0 clamps to max_page_limit (1000), echoed in meta.
    let pagination = apply_pagination(None, Some(0), &cfg);
    assert_eq!(pagination.limit, 1000);
    let resp = datasets_response(&refs, &pagination, &cfg);
    // All three fit under the clamped limit; the echoed limit is the clamp (1000).
    assert_eq!(resp.response.collections.len(), 3);
    assert_eq!(resp.meta.received_request_summary.pagination.limit, 1000);
}

#[test]
fn empty_visible_set_reports_not_exists() {
    let resp = datasets_response(&[], &Pagination::new(0, 10), &crate::fixtures::beacon_cfg());
    assert!(!resp.response_summary.exists);
    assert_eq!(resp.response_summary.num_total_results, Some(0));
    assert!(resp.response.collections.is_empty());
}

/// A dataset whose build-time floor is `dataset_floor` and which serves `pops`.
fn entry_with_disclosure(id: &str, dataset_floor: u32, pops: Option<Vec<String>>) -> DatasetEntry {
    let mut e = entry(id, LocalizedText::Plain("t".to_owned()), None);
    e.config.min_allele_count = dataset_floor;
    e.metadata.populations = pops;
    e
}

#[test]
fn datasets_entry_discloses_assembly_populations_and_the_effective_floor() {
    // Without this a client cannot tell whether a missing population was never in the
    // dataset or was suppressed, nor which assembly to query. Absence reads as zero.
    let mut cfg = crate::fixtures::beacon_cfg();
    cfg.min_allele_count = 2; // node-wide floor
    let entries = [entry_with_disclosure(
        "GDI-EE-UTARTU-20260409143052837",
        5, // dataset floor; effective = max(2, 5) = 5
        Some(vec!["EE".to_owned(), "Total".to_owned()]),
    )];
    let refs: Vec<&DatasetEntry> = entries.iter().collect();
    let resp = datasets_response(&refs, &Pagination::new(0, 10), &cfg);
    let v = serde_json::to_value(&resp).expect("serializes");
    let d = &v["response"]["collections"][0]["gdiDatasetInfo"];

    assert_eq!(d["assembly"], "GRCh38");
    assert_eq!(d["populations"][0], "EE");
    assert_eq!(d["populations"][1], "Total");
    assert_eq!(
        d["minAlleleCount"], 5,
        "the effective floor is max(node, dataset) — disclosing the dataset's alone would understate suppression"
    );
}

#[test]
fn a_dataset_with_no_recorded_populations_omits_the_key_rather_than_claiming_none() {
    let cfg = crate::fixtures::beacon_cfg();
    let entries = [entry_with_disclosure(
        "GDI-EE-UTARTU-20260409143052837",
        0,
        None,
    )];
    let refs: Vec<&DatasetEntry> = entries.iter().collect();
    let v = serde_json::to_value(datasets_response(&refs, &Pagination::new(0, 10), &cfg))
        .expect("serializes");
    let d = &v["response"]["collections"][0]["gdiDatasetInfo"];
    assert_eq!(d["assembly"], "GRCh38");
    assert_eq!(d["minAlleleCount"], 0);
    assert!(
        d.get("populations").is_none(),
        "an older manifest advertises no set, not an empty one"
    );
}
