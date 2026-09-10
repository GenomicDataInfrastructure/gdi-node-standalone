//! The out-of-band conformance harness producer.
//!
//! This test ingests a small fixture corpus: three catalogs, one of them empty; a
//! fully-enriched dataset carrying every optional and recommended field; a minimal dataset
//! with all of them absent; a multi-VCF dataset aggregated from two source VCFs; a hidden
//! dataset; and an errored dataset. It starts the FDP router and crawls the live FDP the way
//! a harvester does: fetch `/fairdp` with `Accept: text/turtle`, walk `ldp:contains`
//! breadth-first, fetch each catalog, dataset and distribution URL separately, and union
//! every fetched Turtle into `target/conformance/union.ttl`. Validating the crawled union
//! rather than each file in isolation is what exercises the cross-resource links.
//!
//! It then invokes the Python conformance checks (`conformance/check_fdp.py`,
//! `conformance/check_ckanext.py`) over that union via the conformance venv,
//! asserting that pySHACL conforms on both shape sets, with only the `dct:hasPart` minCount-0
//! relaxation, and that the consumer parser round-trips the graph.
//!
//! The test is `#[ignore]` because it needs the Python venv. Run it with `--ignored` and
//! `GDI_FDP_VENV` or `GDI_FDP_PYTHON` pointing at the venv. See `conformance/README.md`.
#![allow(
    clippy::disallowed_methods,
    reason = "test/bench code writes plain files: durability and atomicity are not properties under test"
)]
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::{DatasetEntry, StatusIndex};
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::convert::{ConvertOptions, convert_vcf};
use gdi_node_standalone_core::ingest::ingest_staging_dir;
use gdi_node_standalone_core::model::{
    Agent, Assembly, ContactPoint, DatasetMode, LocalizedText, Manifest, ManifestConfig,
    ManifestMetadata, OtherIdentifier,
};
use gdi_node_standalone_core::parquet_io::DatasetEncryptor;
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use tower::ServiceExt as _; // for `oneshot`

const BASE_URL: &str = "https://test.example.org";
const CATALOG_A: &str = "gdi-aggregated";
const CATALOG_B: &str = "synthetic-data";
// A third configured catalog with no datasets, which exercises the empty-catalog
// `dct:hasPart` minCount-0 relaxation, the only shape relaxation in the harness.
const CATALOG_EMPTY: &str = "rare-disease-data";

// A fully-enriched visible dataset (every optional + recommended field present).
const ID_FULL: &str = "GDI-EE-UTARTU-20260409143052837";
// A minimal visible dataset (optional + recommended fields absent).
const ID_MINIMAL: &str = "GDI-EE-UTARTU-20260410090000000";
// A visible dataset in the second (synthetic) catalog.
const ID_SYNTH: &str = "GDI-EE-UTARTU-20260411110000000";
// A visible dataset aggregated from two source VCFs: the records of both are served as one
// dataset, with two `allele-freq.*.parquet` files on distinct contigs.
const ID_MULTI: &str = "GDI-EE-UTARTU-20260412120000000";
// A hidden dataset — never reached by the crawl.
const ID_HIDDEN: &str = "GDI-EE-UTARTU-20260409143052999";
// An errored dataset — never reached by the crawl.
const ID_ERROR: &str = "GDI-EE-UTARTU-20260409143053111";

const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";
const DCAT_DISTRIBUTION: &str = "http://www.w3.org/ns/dcat#distribution";
// The RDF class IRIs, as opposed to the `dcat#distribution` predicate above. A subject typed
// with one of these is emitted only by that resource's own record, so its presence proves the
// record was fetched rather than merely referenced by a parent catalog.
const DCAT_DATASET_CLASS: &str = "http://www.w3.org/ns/dcat#Dataset";
const DCAT_DISTRIBUTION_CLASS: &str = "http://www.w3.org/ns/dcat#Distribution";
const DCAT_CATALOG_CLASS: &str = "http://www.w3.org/ns/dcat#Catalog";

/// The base, fully-enriched manifest for a dataset in `catalog`.
fn enriched_manifest(id: &str, catalog: &str, number_of_records: u64) -> Manifest {
    let mut title = BTreeMap::new();
    title.insert("en".to_owned(), "GoE Estonia aggregated AFs".to_owned());
    title.insert("et".to_owned(), "GoE Eesti koondsagedused".to_owned());

    let mut description = BTreeMap::new();
    description.insert(
        "en".to_owned(),
        "Aggregated allele frequencies for the GoE Estonia cohort.".to_owned(),
    );
    description.insert(
        "et".to_owned(),
        "GoE Eesti kohordi koondatud alleelisagedused.".to_owned(),
    );

    Manifest {
        payload: None,
        metadata: ManifestMetadata {
            dataset_id: id.to_owned(),
            catalog: catalog.to_owned(),
            title: LocalizedText::Map(title),
            // Bilingual, like the title above, so the crawled union carries language-tagged
            // `dct:description` literals. `DatasetShape` declares `sh:uniqueLang` on this
            // path, and `check_fdp_negative.py` can exercise that rule only where the data
            // has language tags: with a plain literal the mutation has no language to
            // duplicate and the site is skipped.
            description: Some(LocalizedText::Map(description)),
            access_rights: "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
                .to_owned(),
            applicable_legislation: vec!["http://data.europa.eu/eli/reg/2025/327/oj".to_owned()],
            license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
            creator: vec![Agent {
                name: "Genome of Europe - EE node".to_owned(),
            }],
            health_category: vec![
                "http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic".to_owned(),
            ],
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
                // Distinct from homepage (see fairdp/tests/render.rs).
                has_url: Some("https://gdi.ut.ee/contact".to_owned()),
            }),
            number_of_records: Some(number_of_records),
            populations: None,
        },
        files: Vec::new(),
        internal: gdi_node_standalone_core::model::Internal::default(),
        config: ManifestConfig {
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
            generated_by: "test".to_owned(),
        },
    }
}

/// A minimal manifest: every optional and recommended field stripped to the mandatory core.
///
/// `description` stays. The gdi-metadata `DatasetShape` mandates `dct:description` with
/// `sh:minCount 1`, so it is part of the mandatory core rather than an optional field.
fn minimal_manifest(id: &str, catalog: &str, number_of_records: u64) -> Manifest {
    let mut m = enriched_manifest(id, catalog, number_of_records);
    m.metadata.title = LocalizedText::Plain("Minimal aggregated AFs".to_owned());
    m.metadata.description = Some(LocalizedText::Plain(
        "A minimal aggregated allele-frequency dataset with no optional fields.".to_owned(),
    ));
    m.metadata.keywords = None;
    m.metadata.number_of_unique_individuals = None;
    m.metadata.conforms_to = None;
    m.metadata.type_ = None;
    m.metadata.legal_basis = None;
    m.metadata.is_referenced_by = None;
    m.metadata.other_identifier = None;
    m.metadata.contact_point = None;
    m
}

/// Convert + ingest the COVID VCF under `manifest`, returning the cache entry.
fn ingest(
    parent: &Path,
    data_dir: &Path,
    manifest: &Manifest,
    state: DatasetState,
) -> DatasetEntry {
    let id = manifest.metadata.dataset_id.clone();
    let staging = parent.join(format!("staging-{id}"));
    std::fs::create_dir_all(&staging).unwrap();
    let vcf = test_util::covid_vcf_path();
    convert_vcf(
        &vcf,
        &staging,
        &ConvertOptions {
            assembly: "GRCh38".to_owned(),
            block_range: 10_000_000,
            min_allele_count: 0,
        },
    )
    .unwrap();
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(manifest).unwrap(),
    )
    .unwrap();
    let mut catalogs = BTreeMap::new();
    catalogs.insert(CATALOG_A.to_owned(), "GoE Aggregated".to_owned());
    catalogs.insert(CATALOG_B.to_owned(), "Synthetic Data".to_owned());
    catalogs.insert(CATALOG_EMPTY.to_owned(), "Rare Disease Data".to_owned());
    let ok = ingest_staging_dir(
        &staging,
        data_dir,
        &ParquetCaps::default(),
        &catalogs,
        &DatasetEncryptor::plaintext(),
    )
    .unwrap();
    DatasetEntry {
        id: ok.id,
        metadata: ok.metadata,
        config: ok.config,
        state,
        metadata_modified: None,
    }
}

#[test]
fn ingest_rejects_manifest_with_wrong_number_of_records() {
    // The ingest gate recomputes `numberOfRecords` from the parquet and rejects a manifest
    // whose declared count disagrees with the data, so a hand-assembled package cannot
    // advertise a false record count on the public RDF plane. The COVID VCF yields one
    // distinct variant, so a manifest declaring 999 is refused.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let staging = tmp.path().join("staging-wrongcount");
    std::fs::create_dir_all(&staging).unwrap();
    let vcf = test_util::covid_vcf_path();
    convert_vcf(
        &vcf,
        &staging,
        &ConvertOptions {
            assembly: "GRCh38".to_owned(),
            block_range: 10_000_000,
            min_allele_count: 0,
        },
    )
    .unwrap();
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&enriched_manifest(ID_FULL, CATALOG_A, 999)).unwrap(),
    )
    .unwrap();
    let mut catalogs = BTreeMap::new();
    catalogs.insert(CATALOG_A.to_owned(), "GoE Aggregated".to_owned());
    let err = ingest_staging_dir(
        &staging,
        &data_dir,
        &ParquetCaps::default(),
        &catalogs,
        &DatasetEncryptor::plaintext(),
    )
    .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("numberOfRecords") && msg.contains("999"),
        "expected a numberOfRecords mismatch rejection, got: {msg}"
    );
}

/// Convert + ingest a dataset built from **two** source VCFs into a single staging
/// dir — the way `gdi-dataset-tool`'s `convert_vcf_group` builds a multi-VCF
/// dataset (each `convert_vcf` writes its own `allele-freq.*.{vcfid}.parquet`
/// files, so they coexist under one dataset). Returns the cache entry with its
/// `number_of_records` set to the aggregate across both VCFs.
fn ingest_multi(
    parent: &Path,
    data_dir: &Path,
    manifest: &Manifest,
    state: DatasetState,
) -> DatasetEntry {
    let id = manifest.metadata.dataset_id.clone();
    let staging = parent.join(format!("staging-{id}"));
    std::fs::create_dir_all(&staging).unwrap();
    let opts = ConvertOptions {
        assembly: "GRCh38".to_owned(),
        block_range: 10_000_000,
        min_allele_count: 0,
    };
    // Two distinct source VCFs (different contigs) aggregated into one dataset.
    let vcf_a = test_util::covid_vcf_path();
    let vcf_b = parent.join("COVID.monogneic.aggregate.AFs.chr7.GRCh38.vcf");
    std::fs::write(&vcf_b, test_util::covid_chr7_vcf_bytes()).unwrap();
    let out_a = convert_vcf(&vcf_a, &staging, &opts).unwrap();
    let out_b = convert_vcf(&vcf_b, &staging, &opts).unwrap();
    // Distinct VCFs => distinct vcfids => no parquet-file collision; both sets of
    // records live under the one dataset.
    assert_ne!(
        out_a.vcfid, out_b.vcfid,
        "the two source VCFs must have distinct vcfids"
    );

    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(manifest).unwrap(),
    )
    .unwrap();
    let mut catalogs = BTreeMap::new();
    catalogs.insert(CATALOG_A.to_owned(), "GoE Aggregated".to_owned());
    catalogs.insert(CATALOG_B.to_owned(), "Synthetic Data".to_owned());
    catalogs.insert(CATALOG_EMPTY.to_owned(), "Rare Disease Data".to_owned());
    let ok = ingest_staging_dir(
        &staging,
        data_dir,
        &ParquetCaps::default(),
        &catalogs,
        &DatasetEncryptor::plaintext(),
    )
    .unwrap();

    // The published dataset dir carries both VCFs' parquet files: aggregation across VCFs is
    // the union of their `allele-freq.*.parquet` files.
    let dataset_dir = data_dir.join(&ok.id);
    let parquet_count = std::fs::read_dir(&dataset_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("allele-freq.") && n.ends_with(".parquet"))
        })
        .count();
    assert!(
        parquet_count >= 2,
        "multi-VCF dataset must publish >=2 allele-freq parquet files (got {parquet_count})"
    );

    DatasetEntry {
        id: ok.id,
        metadata: ok.metadata,
        config: ok.config,
        state,
        metadata_modified: None,
    }
}

/// A service config with two catalogs (one populated, one to receive a synthetic
/// dataset) and the `[fairdp]` node identity.
fn test_config(data_dir: &Path) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "{BASE_URL}"
data_dir = "{}"

[catalogs]
{CATALOG_A} = "GoE Aggregated"
{CATALOG_B} = "Synthetic Data"
{CATALOG_EMPTY} = "Rare Disease Data"

[beacon]
aggregated_base_path = "/beacon/v2"
id = "org.test.beacon"
name = "Test Beacon"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"

[fairdp]
title = "GDI Estonia FAIR Data Point"
description = "Aggregated genomic metadata for GDI Estonia"
issued = "2026-01-01T00:00:00Z"
license = "https://creativecommons.org/licenses/by/4.0/"
theme = ["http://publications.europa.eu/resource/authority/data-theme/HEAL"]
applicable_legislation = ["http://data.europa.eu/eli/reg/2025/327/oj"]

[fairdp.publisher]
name = "University of Tartu"
homepage = "https://gdi.ut.ee"
mbox = "mailto:gdi@example.org"
[fairdp.publisher.contact_point]
fn = "GDI Estonia"
has_email = "mailto:gdi@example.org"
has_url = "https://gdi.ut.ee/contact"

[fairdp.hdab]
name = "Estonian HDAB"
[fairdp.hdab.contact_point]
fn = "Estonian HDAB"
has_email = "mailto:hdab@example.org"
"#,
        data_dir.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

/// Build the corpus `AppState`.
fn corpus_state() -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let full = ingest(
        tmp.path(),
        &data_dir,
        // The single-VCF fixtures all ingest the COVID VCF, which holds 1 distinct variant.
        // Ingest recomputes and verifies `numberOfRecords`, so the manifest must declare the
        // true count.
        &enriched_manifest(ID_FULL, CATALOG_A, 1),
        DatasetState::Visible,
    );
    let minimal = ingest(
        tmp.path(),
        &data_dir,
        &minimal_manifest(ID_MINIMAL, CATALOG_A, 1),
        DatasetState::Visible,
    );
    let synth = ingest(
        tmp.path(),
        &data_dir,
        &enriched_manifest(ID_SYNTH, CATALOG_B, 1),
        DatasetState::Visible,
    );
    // A multi-VCF dataset: aggregated from two source VCFs.
    // `number_of_records` is the aggregate across both VCFs (1 + 1 = 2).
    let multi = ingest_multi(
        tmp.path(),
        &data_dir,
        &enriched_manifest(ID_MULTI, CATALOG_A, 2),
        DatasetState::Visible,
    );
    let hidden = ingest(
        tmp.path(),
        &data_dir,
        &enriched_manifest(ID_HIDDEN, CATALOG_A, 1),
        DatasetState::Hidden,
    );
    let errored = ingest(
        tmp.path(),
        &data_dir,
        &enriched_manifest(ID_ERROR, CATALOG_A, 1),
        DatasetState::Error,
    );

    let config = test_config(&data_dir);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    for entry in [full, minimal, synth, multi, hidden, errored] {
        state.cache.insert(
            gdi_node_standalone_core::cache::StatusWrite::unshared(),
            entry,
        );
    }
    (state, tmp)
}

/// Map an absolute resource IRI under `BASE_URL` to its request path.
fn iri_to_path(iri: &str) -> Option<String> {
    iri.strip_prefix(BASE_URL).map(ToOwned::to_owned)
}

/// Fetch one resource as Turtle: returns the raw Turtle bytes on 200, else None.
async fn fetch_turtle(router: &Router, path: &str) -> Option<String> {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("accept", "text/turtle")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    if resp.status() != StatusCode::OK {
        return None;
    }
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    Some(String::from_utf8(bytes.to_vec()).unwrap())
}

/// The object IRIs of `(subject?, predicate, IRI)` triples in `ttl` — used only
/// for the BFS (we parse each fetched doc to follow `ldp:contains` /
/// `dcat:distribution`). Subject filtering is unnecessary: each fetched resource
/// graph is the single record's own triples.
fn iri_objects_of(ttl: &str, predicate: &str) -> Vec<String> {
    let mut out = Vec::new();
    for triple in oxttl::TurtleParser::new().for_slice(ttl.as_bytes()) {
        let triple = triple.unwrap();
        if triple.predicate.as_str() == predicate
            && let oxrdf::Term::NamedNode(n) = &triple.object
        {
            out.push(n.as_str().to_owned());
        }
    }
    out
}

/// The subject IRIs of `(IRI, rdf:type, type_iri)` triples in `ttl`.
///
/// A resource's `rdf:type` triple is emitted only by that resource's own record
/// (`dataset_graph` or `distribution_graph`), never by a catalog that lists it via
/// `ldp:contains` or `dct:hasPart`. A subject appearing here therefore proves the record was
/// fetched and unioned. A substring check on the IRI string would pass on the catalog's
/// reference alone, even with the record's own handler broken.
fn subjects_of_type(ttl: &str, type_iri: &str) -> BTreeSet<String> {
    const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
    let mut out = BTreeSet::new();
    for triple in oxttl::TurtleParser::new().for_slice(ttl.as_bytes()) {
        let triple = triple.unwrap();
        if triple.predicate.as_str() == RDF_TYPE
            && let oxrdf::Term::NamedNode(obj) = &triple.object
            && obj.as_str() == type_iri
            && let oxrdf::NamedOrBlankNode::NamedNode(subj) = &triple.subject
        {
            out.insert(subj.as_str().to_owned());
        }
    }
    out
}

/// The serialized blank-node labels (`_:label`) present in a Turtle document — the
/// labels as written by the serializer, not the parsed graph's nodes.
///
/// `crawl_union` concatenates every fetched document and parses the result as one Turtle
/// graph, so a label reused across two documents would merge two distinct blank nodes, since
/// Turtle scopes labels per document. A real FDP harvester avoids this by parsing each
/// fetched resource into its own graph. Extracting the raw labels here lets the test assert
/// the concatenated union is collision-free.
fn blank_node_labels(ttl: &str) -> BTreeSet<String> {
    let bytes = ttl.as_bytes();
    let mut out = BTreeSet::new();
    for (pos, _) in ttl.match_indices("_:") {
        let start = pos + 2;
        let mut end = start;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'-'))
        {
            end += 1;
        }
        if end > start {
            out.insert(ttl[start..end].to_owned());
        }
    }
    out
}

/// Record `ttl`'s blank-node labels into `seen`, asserting none already appeared in another
/// fetched document, which the string-concatenated union would merge into one node.
///
/// The assertion cannot fail while the FDP graph builder mints blank nodes with
/// `BlankNode::default()`, which oxrdf implements as a random 128-bit id. It is a tripwire on
/// that implementation detail: the concatenated union is sound only because labels are
/// globally unique, and a switch to deterministic per-document labels (`_:b0`, `_:b1`, …)
/// would start every document at `_:b0`.
fn record_bnode_labels(ttl: &str, doc_id: &str, seen: &mut BTreeMap<String, String>) {
    for label in blank_node_labels(ttl) {
        match seen.get(&label) {
            Some(prev) => assert!(
                prev == doc_id,
                "blank-node label `_:{label}` appears in two fetched FDP documents \
                 ({prev} and {doc_id}); concatenating them into one union graph would \
                 merge two distinct blank nodes. Parse each fetched resource into its \
                 own graph and RDF-merge (as the real harvester does) instead."
            ),
            None => {
                seen.insert(label, doc_id.to_owned());
            }
        }
    }
}

/// Crawl the FDP harvester-style and return the unioned Turtle (every fetched
/// resource's Turtle concatenated — rdflib/pyShACL parse the union).
async fn crawl_union(router: &Router) -> String {
    let mut union = String::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    // Guard: the concat-union is only sound if no blank-node label is reused across
    // two fetched documents (unlike the real harvester, which parses each separately).
    let mut seen_bnodes: BTreeMap<String, String> = BTreeMap::new();

    let root_ttl = fetch_turtle(router, "/fairdp")
        .await
        .expect("the FDP root must dereference");
    record_bnode_labels(&root_ttl, "/fairdp", &mut seen_bnodes);
    union.push_str(&root_ttl);
    union.push('\n');

    // BFS over ldp:contains: root -> catalogs -> datasets. A dataset's
    // distribution is dereferenced separately via dcat:distribution.
    let mut queue: VecDeque<String> = VecDeque::new();
    for target in iri_objects_of(&root_ttl, LDP_CONTAINS) {
        queue.push_back(target);
    }

    while let Some(iri) = queue.pop_front() {
        if !visited.insert(iri.clone()) {
            continue;
        }
        let Some(path) = iri_to_path(&iri) else {
            // A non-node IRI cannot appear as an ldp:contains target of our own FDP;
            // skip anything outside BASE_URL defensively.
            continue;
        };
        // An `ldp:contains` target, a catalog or dataset record, has to dereference. A silent
        // `continue` here would let a broken `/fairdp/dataset/{id}` handler drop the record
        // from the union while the gate still passed, so fail hard instead.
        let ttl = fetch_turtle(router, &path).await.unwrap_or_else(|| {
            panic!("ldp:contains target {iri} did not dereference (non-200); the FDP crawl gate must not pass with a missing record")
        });
        record_bnode_labels(&ttl, &path, &mut seen_bnodes);
        union.push_str(&ttl);
        union.push('\n');

        // Dereference any distribution separately; it is not an `ldp:contains` child. A
        // referenced distribution also has to dereference, for the same reason.
        for dist_iri in iri_objects_of(&ttl, DCAT_DISTRIBUTION) {
            if !visited.insert(dist_iri.clone()) {
                continue;
            }
            let Some(dist_path) = iri_to_path(&dist_iri) else {
                continue;
            };
            let dist_ttl = fetch_turtle(router, &dist_path).await.unwrap_or_else(|| {
                panic!("dcat:distribution {dist_iri} did not dereference (non-200)")
            });
            record_bnode_labels(&dist_ttl, &dist_path, &mut seen_bnodes);
            union.push_str(&dist_ttl);
            union.push('\n');
        }

        // Continue the BFS through ldp:contains only.
        for target in iri_objects_of(&ttl, LDP_CONTAINS) {
            queue.push_back(target);
        }
    }
    union
}

/// The conformance directory (`<repo>/conformance`).
fn conformance_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance")
        .canonicalize()
        .expect("conformance/ exists")
}

/// Resolve the conformance venv python: `GDI_FDP_PYTHON` (a python path), else
/// `GDI_FDP_VENV`/bin/python, else the default venv path under the system temp dir.
fn venv_python() -> PathBuf {
    if let Ok(py) = std::env::var("GDI_FDP_PYTHON") {
        return PathBuf::from(py);
    }
    if let Ok(venv) = std::env::var("GDI_FDP_VENV") {
        return PathBuf::from(venv).join("bin/python");
    }
    // The fallback when neither GDI_FDP_PYTHON nor GDI_FDP_VENV is set. If this interpreter
    // is absent the test fails hard: `run_check` panics on the failed spawn rather than
    // reporting a false green.
    std::env::temp_dir().join("gdi-node-standalone-fdp-venv/bin/python")
}

/// Run a Python conformance script over the union file, returning (success,
/// combined stdout+stderr). `must_pass` controls whether a non-zero exit is an
/// assertion failure (true for pySHACL, the must-have) or a graceful skip (the
/// caller decides).
fn run_check(py: &Path, script: &str, union: &Path) -> (bool, String) {
    let script_path = conformance_dir().join(script);
    let output = Command::new(py)
        .arg(&script_path)
        .arg(union)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", py.display()));
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), combined)
}

#[tokio::test]
#[ignore = "needs the Python conformance venv; run with --ignored and GDI_FDP_PYTHON/GDI_FDP_VENV"]
async fn fdp_union_conforms_to_shapes_and_consumer() {
    let (state, _tmp) = corpus_state();
    let router = build_router(state);
    let union = crawl_union(&router).await;

    // Write the union next to the build so it can be inspected after a failure.
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/conformance");
    std::fs::create_dir_all(&out_dir).unwrap();
    let union_path = out_dir.join("union.ttl");
    std::fs::write(&union_path, &union).unwrap();
    let union_path = union_path.canonicalize().unwrap();
    eprintln!("wrote union graph to {}", union_path.display());

    // The crawl fetched each visible dataset's own record, proven by its `rdf:type
    // dcat:Dataset` triple, which only the dataset record emits. A substring check on the IRI
    // would pass on the catalog's `ldp:contains` or `dct:hasPart` reference alone, even with
    // the dataset's own `/fairdp/dataset/{id}` handler returning a 500.
    let dataset_subjects = subjects_of_type(&union, DCAT_DATASET_CLASS);
    for (id, label) in [
        (ID_FULL, "fully-enriched"),
        (ID_MINIMAL, "minimal"),
        (ID_SYNTH, "synthetic-catalog"),
        (ID_MULTI, "multi-VCF"),
    ] {
        let iri = format!("{BASE_URL}/fairdp/dataset/{id}");
        assert!(
            dataset_subjects.contains(&iri),
            "union missing the FETCHED {label} dataset record (no `{iri}` rdf:type dcat:Dataset \
             triple — the dataset's own handler may not have served it)"
        );
    }
    // Each visible dataset's distribution record must also have been fetched (its
    // `rdf:type dcat:Distribution` triple is only in the distribution record). The
    // four visible datasets each generate exactly one distribution.
    let dist_subjects = subjects_of_type(&union, DCAT_DISTRIBUTION_CLASS);
    assert!(
        dist_subjects.len() >= 4,
        "union missing fetched distribution records: found {} typed dcat:Distribution subjects, expected >= 4",
        dist_subjects.len()
    );
    assert!(
        !union.contains(&format!("dataset/{ID_HIDDEN}")),
        "union wrongly reached the hidden dataset"
    );
    assert!(
        !union.contains(&format!("dataset/{ID_ERROR}")),
        "union wrongly reached the errored dataset"
    );
    // The empty catalog is crawled under its stable URI but carries no `dct:hasPart`, so the
    // graph conforms only because of the minCount-0 relaxation in `fdp-catalog.ttl`. This
    // line is what exercises that relaxation.
    //
    // It is not a substring check. The FDP root's own `ldp:contains` reference carries the
    // IRI, so a substring assertion would pass on the root alone, even with a
    // `/fairdp/catalog/{id}` handler returning `200 OK` and an empty body, since
    // `fetch_turtle` returns `Some("")` on a 200. Require the catalog's own record instead,
    // proven by the `rdf:type dcat:Catalog` triple only that record emits.
    let catalog_subjects = subjects_of_type(&union, DCAT_CATALOG_CLASS);
    let empty_catalog_iri = format!("{BASE_URL}/fairdp/catalog/{CATALOG_EMPTY}");
    assert!(
        catalog_subjects.contains(&empty_catalog_iri),
        "union missing the fetched empty-catalog record (no `{empty_catalog_iri}` \
         rdf:type dcat:Catalog triple). The minCount-0 `dct:hasPart` relaxation in \
         fdp-catalog.ttl is only exercised when this record is really served."
    );

    let py = venv_python();

    // pySHACL is required: both shape sets must conform.
    let (fdp_ok, fdp_out) = run_check(&py, "check_fdp.py", &union_path);
    println!("{fdp_out}");
    assert!(fdp_ok, "pySHACL conformance failed:\n{fdp_out}");

    // Negative meta-validation, also required: the shapes reject a mutated union, where each
    // mutation drops one mandatory triple. This shows the shapes discriminate. A
    // positive-only suite would still report conformance with a `sh:targetClass` typo that
    // disabled a whole shape.
    let (neg_ok, neg_out) = run_check(&py, "check_fdp_negative.py", &union_path);
    println!("{neg_out}");
    assert!(
        neg_ok,
        "negative SHACL meta-validation failed (the shapes did not reject a malformed graph):\n{neg_out}"
    );

    // ckanext-dcat is optional: it degrades gracefully, exiting 0 with a skip note if the
    // standalone wiring fails. A success here means it either round-tripped or skipped.
    let (ckan_ok, ckan_out) = run_check(&py, "check_ckanext.py", &union_path);
    println!("{ckan_out}");
    assert!(
        ckan_ok,
        "ckanext-dcat check returned a hard failure (it should degrade gracefully):\n{ckan_out}"
    );
}

/// The multi-VCF corpus dataset ingests and serves through the live FDP crawl. It needs no
/// Python venv, so it runs in the standard suite. It pins that the dataset is reached by the
/// harvester-style crawl, and that the node serves the dataset's `numberOfRecords`, here 2,
/// the build-time aggregate of both source VCFs.
///
/// The node serves the manifest's recorded count. The cross-VCF aggregation arithmetic is a
/// `cmd_build` concern, covered by `distinct_number_of_records` in the dataset tool.
#[tokio::test]
async fn multi_vcf_dataset_serves_its_aggregate_record_count() {
    let (state, _tmp) = corpus_state();
    let router = build_router(state);
    let union = crawl_union(&router).await;

    // The crawl reached the multi-VCF dataset's own record, proven by the `rdf:type
    // dcat:Dataset` triple only that record emits. A substring would be satisfied by the
    // listing catalog's reference to the same IRI.
    let dataset_iri = format!("{BASE_URL}/fairdp/dataset/{ID_MULTI}");
    assert!(
        subjects_of_type(&union, DCAT_DATASET_CLASS).contains(&dataset_iri),
        "the crawl must reach the multi-VCF dataset's own record"
    );

    // Fetch just the multi-VCF dataset record and confirm the node serves its recorded
    // `numberOfRecords`, 2, the build-time aggregate of both source VCFs.
    let ttl = fetch_turtle(&router, &format!("/fairdp/dataset/{ID_MULTI}"))
        .await
        .expect("the multi-VCF dataset must dereference");
    let count = number_of_records_in(&ttl)
        .expect("the multi-VCF dataset record must carry healthdcatap:numberOfRecords");
    assert_eq!(
        count, 2,
        "the node must serve the multi-VCF dataset's aggregate record count (got {count})"
    );
}

/// Extract the single `healthdcatap:numberOfRecords` literal value from a dataset's
/// Turtle, if present.
fn number_of_records_in(ttl: &str) -> Option<u64> {
    const NUMBER_OF_RECORDS: &str = "http://healthdataportal.eu/ns/health#numberOfRecords";
    for triple in oxttl::TurtleParser::new().for_slice(ttl.as_bytes()) {
        let triple = triple.unwrap();
        if triple.predicate.as_str() == NUMBER_OF_RECORDS
            && let oxrdf::Term::Literal(lit) = &triple.object
        {
            return lit.value().parse().ok();
        }
    }
    None
}
