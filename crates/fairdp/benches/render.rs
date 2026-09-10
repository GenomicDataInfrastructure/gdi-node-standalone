//! Criterion benchmark for the FDP RDF render hot path.
//!
//! Every `/fairdp/...` request builds an [`oxrdf::Graph`] fresh (dataset, catalog, or
//! root) and serializes it to the negotiated format (see
//! `crates/gdi-node-standalone/src/fairdp_http.rs`); neither the graph nor the
//! serialized body is cached. That build-then-serialize pair is the per-request cost,
//! and it is pure CPU, so it is worth tracking as the catalog of datasets grows.
//!
//! Two entry points are benched, each in both formats:
//! * `dataset_turtle` / `dataset_jsonld` — `GET /fairdp/dataset/{id}`, the
//!   single-resource render (the most frequently hit FDP route);
//! * `catalog_turtle` / `catalog_jsonld` — `GET /fairdp/catalog/{id}` over a synthetic
//!   `N_DATASETS`-entry catalog, so the membership-triple and sort cost is measured at a
//!   realistic scale rather than the one-dataset case.
//!
//! `distribution_graph` is not benched separately: it runs through the same
//! `GraphBuilder` as `dataset_graph` (see `crates/fairdp/src/graph.rs`), so it would
//! track the same cost as `dataset_turtle`/`dataset_jsonld`.
//!
//! The fixtures mirror the integration tests' `covid_entry` / `fairdp_config` helpers,
//! so the bench renders a representative dataset (localized title, contact point,
//! `otherIdentifier`, legal basis) rather than a minimal stub.

use std::collections::BTreeMap;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use gdi_node_standalone_core::cache::DatasetEntry;
use gdi_node_standalone_core::config::{
    ContactPointCfg, FairdpConfig, FairdpHdab, FairdpPublisher,
};
use gdi_node_standalone_core::model::{
    Agent, Assembly, ContactPoint, DatasetMode, LocalizedText, ManifestConfig, ManifestMetadata,
    OtherIdentifier,
};
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_fairdp::{
    FdpContext, catalog_graph, dataset_graph, serialize_jsonld, serialize_turtle,
};

const BASE_URL: &str = "https://gdi-ee.example.org";
const BEACON_PATH: &str = "/beacon/v2";
const CATALOG_ID: &str = "gdi-aggregated";
const CATALOG_TITLE: &str = "GoE aggregated catalog";

/// A representative COVID-derived dataset entry (the manifest.json fixture fields),
/// exercising every model branch: localized title and description as a language map,
/// lists, the `otherIdentifier` blank node, and a contact point. Mirrors the integration
/// tests' `covid_entry` fixture.
fn covid_entry(dataset_id: &str) -> DatasetEntry {
    let mut title = BTreeMap::new();
    title.insert("en".to_owned(), "GoE Estonia aggregated AFs".to_owned());
    title.insert("et".to_owned(), "GoE Eesti koondsagedused".to_owned());

    let metadata = ManifestMetadata {
        dataset_id: dataset_id.to_owned(),
        catalog: CATALOG_ID.to_owned(),
        title: LocalizedText::Map(title),
        description: Some(LocalizedText::Plain(
            "Aggregated allele frequencies for the GoE Estonia cohort.".to_owned(),
        )),
        access_rights: "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
            .to_owned(),
        applicable_legislation: vec!["http://data.europa.eu/eli/reg/2025/327/oj".to_owned()],
        license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
        creator: vec![Agent {
            name: "Genome of Europe - EE node".to_owned(),
        }],
        health_category: vec!["http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic".to_owned()],
        keywords: Some(vec!["allele-frequency".to_owned(), "genomics".to_owned()]),
        number_of_unique_individuals: Some(1234),
        conforms_to: Some(vec!["http://data.gdi.eu/core/p2/1MGCompliant".to_owned()]),
        type_: None,
        legal_basis: Some(vec!["https://w3id.org/dpv#Consent".to_owned()]),
        is_referenced_by: Some(vec!["https://doi.org/10.1234/example".to_owned()]),
        other_identifier: Some(vec![OtherIdentifier {
            notation: "DOI-12345".to_owned(),
            schema_agency: Some("DataCite".to_owned()),
            name: Some("Example identifier".to_owned()),
        }]),
        contact_point: Some(ContactPoint {
            fn_: Some("Data team".to_owned()),
            has_email: Some("mailto:data@example.org".to_owned()),
            has_url: None,
        }),
        number_of_records: Some(123_456),
        populations: None,
    };

    let config = ManifestConfig {
        mode: DatasetMode::Aggregated,
        block_range: 10_000_000,
        af_source: Some("The Genome of Europe".to_owned()),
        af_source_reference: Some("https://genomeofeurope.eu/".to_owned()),
        min_allele_count: 0,
        hide_lower_counts: None,
        assembly: Assembly {
            reference: "GRCh38".to_owned(),
        },
        manifest_version: 1,
        generated_by: "gdi-dataset-tool/bench".to_owned(),
    };

    DatasetEntry {
        id: dataset_id.to_owned(),
        metadata,
        config,
        state: DatasetState::Visible,
        metadata_modified: None,
    }
}

/// The node-identity FDP config (publisher, HDAB, theme, license). Mirrors the
/// integration tests' `fairdp_config` fixture.
fn fairdp_config() -> FairdpConfig {
    FairdpConfig {
        title: "GDI Estonia FAIR Data Point".to_owned(),
        description: Some("Aggregated genomic metadata for GDI Estonia".to_owned()),
        issued: "2026-01-01T00:00:00Z".to_owned(),
        license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
        language: "http://publications.europa.eu/resource/authority/language/ENG".to_owned(),
        theme: vec!["http://publications.europa.eu/resource/authority/data-theme/HEAL".to_owned()],
        theme_taxonomy: None,
        applicable_legislation: vec!["http://data.europa.eu/eli/reg/2025/327/oj".to_owned()],
        publisher: FairdpPublisher {
            name: "University of Tartu".to_owned(),
            homepage: Some("https://gdi.ut.ee".to_owned()),
            mbox: Some("mailto:gdi@example.org".to_owned()),
            contact_point: ContactPointCfg {
                fn_: "GDI Estonia".to_owned(),
                has_email: "mailto:gdi@example.org".to_owned(),
                has_url: Some("https://gdi.ut.ee".to_owned()),
            },
        },
        hdab: FairdpHdab {
            name: "Estonian HDAB".to_owned(),
            contact_point: ContactPointCfg {
                fn_: "Estonian HDAB".to_owned(),
                has_email: "mailto:hdab@example.org".to_owned(),
                has_url: None,
            },
        },
    }
}

/// Scale for the synthetic catalog bench: large enough that the membership triples and
/// sort dominate the single-dataset case, small enough to stay quick to iterate on.
const N_DATASETS: usize = 200;

/// `N_DATASETS` distinct visible entries in one catalog, each with a unique
/// `datasetId`, so the per-dataset IRIs and membership triples are all distinct, as in a
/// growing catalog rather than one dataset repeated.
fn synthetic_catalog_entries() -> Vec<DatasetEntry> {
    (0..N_DATASETS)
        .map(|i| covid_entry(&format!("GDI-EE-UTARTU-BENCH-{i:06}")))
        .collect()
}

fn bench_render(c: &mut Criterion) {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let dataset = covid_entry("GDI-EE-UTARTU-20260409143052837");
    let catalog_entries = synthetic_catalog_entries();
    let catalog_refs: Vec<&DatasetEntry> = catalog_entries.iter().collect();

    let mut group = c.benchmark_group("fairdp_render");

    // GET /fairdp/dataset/{id}: build + serialize the single-dataset graph.
    group.bench_function("dataset_turtle", |b| {
        b.iter(|| {
            let graph = dataset_graph(black_box(&dataset), black_box(&ctx));
            black_box(serialize_turtle(&graph));
        });
    });
    group.bench_function("dataset_jsonld", |b| {
        b.iter(|| {
            let graph = dataset_graph(black_box(&dataset), black_box(&ctx));
            black_box(serialize_jsonld(&graph));
        });
    });

    // GET /fairdp/catalog/{id}: build + serialize the catalog graph over N_DATASETS
    // visible datasets, the cost that grows with catalog size.
    group.bench_function("catalog_turtle", |b| {
        b.iter(|| {
            let graph = catalog_graph(
                black_box(CATALOG_ID),
                black_box(CATALOG_TITLE),
                black_box(&catalog_refs),
                black_box(&ctx),
            );
            black_box(serialize_turtle(&graph));
        });
    });
    group.bench_function("catalog_jsonld", |b| {
        b.iter(|| {
            let graph = catalog_graph(
                black_box(CATALOG_ID),
                black_box(CATALOG_TITLE),
                black_box(&catalog_refs),
                black_box(&ctx),
            );
            black_box(serialize_jsonld(&graph));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_render);
criterion_main!(benches);
