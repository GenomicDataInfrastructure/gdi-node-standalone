//! GA4GH Beacon v2 wire-schema conformance: drive the node's real `/info`, `/configuration`
//! and `/g_variants` responses in-process and validate the JSON bodies against the vendored
//! GA4GH `beacon-v2` framework JSON Schemas (v2.2.0, draft 2020-12) under
//! `conformance/ga4gh-beacon-v2/` (see its `VENDORED.md`). It also crawls `/map` and
//! validates every endpoint the node advertises against the schema for its entry type — the
//! producer side of what an external GA4GH crawler does, in-process and hermetic (no binary
//! install, no network).
//!
//! The framework schemas cover the envelope only: `beaconResultsets.json` constrains
//! `results` as `{"type": "array", "items": {"type": "object"}}`, which leaves the payload a
//! federated client parses unvalidated. The entity schemas therefore come from two further
//! vendored sets: `conformance/ga4gh-beacon-v2-default-model/`, holding the
//! `genomicVariations` entity that the node's own `meta.returnedSchemas[].schema` URL names,
//! and `conformance/ga4gh-vrs-1.3/`, which the default model `$ref`s by absolute URL. Every
//! `results[]` item of a real `/g_variants` response is validated against them.
//!
//! The golden snapshots in `beacon_info.rs` pin what the node emits, not what the schemas
//! require, so only this test catches a misreading of the `beaconInfoResponse`,
//! `beaconConfigurationResponse`, `beaconResultsetsResponse`, `beaconCountResponse`,
//! `beaconBooleanResponse` or `beaconErrorResponse` wire schemas. The FDP side has its own
//! out-of-band Python analog under `conformance/`.
//!
//! Three facts govern how the vendored trees are served. The framework schemas carry no
//! `$id` and use relative cross-file `$ref`s, so a retrieved document's base URI is the URI
//! it was fetched from; the vendored files preserve the upstream directory layout and are
//! served through a blocking [`Retrieve`] keyed by `https://ga4gh.test/beacon-v2/<relpath>`.
//! The default model refs some documents by absolute upstream URL rather than relatively, so
//! the framework tree is served a second time under [`UPSTREAM_FRAMEWORK_BASE`] and VRS
//! under its real `w3id.org` URI. And `vrs.json` declares draft-07 while everything around
//! it is 2020-12; the retrieved document's own `$schema` selects its dialect, so the mixed
//! graph resolves without a per-document draft override.
#![allow(
    clippy::disallowed_methods,
    reason = "test/bench code writes plain files: durability and atomicity are not properties under test"
)]
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    Agent, Assembly, DatasetMode, LocalizedText, Manifest, ManifestConfig, ManifestMetadata,
};
use gdi_node_standalone_core::parquet_io::DatasetEncryptor;
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use jsonschema::{Draft, Retrieve, Uri, Validator};
use serde_json::Value;
use tower::ServiceExt as _; // for `oneshot`

const DATASET_ID: &str = "GDI-EE-UTARTU-20260409143052837";
const CATALOG: &str = "gdi-aggregated";
/// The aggregated beacon mount prefix (matches `[beacon].aggregated_base_path`).
const BEACON_PREFIX: &str = "/beacon/v2";
/// Synthetic base URI the vendored framework schema tree is served under (the refs are
/// relative, so the scheme and authority are arbitrary; it only has to be a valid base).
const BASE: &str = "https://ga4gh.test/beacon-v2/";
/// The framework tree's real upstream URL prefix. The default-model schemas `$ref`
/// framework files by absolute URL (`…/framework/json/common/ontologyTerm.json`) rather
/// than relatively, so the same vendored files are served a second time under this prefix
/// — and their own relative refs (`./beaconCommonComponents.json`) then resolve to
/// siblings within it. Upstream writes `main` in those URLs, not the pinned tag; the file
/// served is the vendored copy at the pinned commit, which is the stricter reading.
const UPSTREAM_FRAMEWORK_BASE: &str =
    "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/framework/json/";
/// Synthetic base URI the vendored default-model tree is served under. Distinct from
/// [`BASE`] because the model's `../common/…` refs must resolve to the model's `common/`,
/// not the framework's — the two directories hold different files under the same names.
const MODEL_BASE: &str = "https://ga4gh.test/beacon-v2-default-model/";
/// Base URI the vendored VRS 1.3 schema is served under. Not synthetic: the default
/// model `$ref`s `https://w3id.org/ga4gh/schema/vrs/1.3/vrs.json#/definitions/Location`
/// by that absolute URL, so the retriever has to answer under it verbatim.
const VRS_BASE: &str = "https://w3id.org/ga4gh/schema/vrs/1.3/";
/// The default-model entity schema this node serves: the `genomicVariations` record shape
/// that `meta.returnedSchemas[].schema` names, relative to [`MODEL_BASE`].
const GENOMIC_VARIATIONS_SCHEMA: &str = "genomicVariations/defaultSchema.json";

// ===================== vendored-schema retriever =====================

/// Serves every vendored GA4GH file by the base-prefixed relative path it was loaded
/// under ([`BASE`], [`UPSTREAM_FRAMEWORK_BASE`], [`MODEL_BASE`], [`VRS_BASE`]), so both the
/// relative `$ref`s between sibling schemas and the absolute ones the default model makes
/// resolve offline.
struct Ga4ghRetriever {
    schemas: Arc<HashMap<String, Value>>,
}

impl Retrieve for Ga4ghRetriever {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.schemas
            .get(uri.as_str())
            .cloned()
            .ok_or_else(|| format!("no vendored GA4GH schema for {uri}").into())
    }
}

fn conformance_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

fn schemas_dir() -> PathBuf {
    conformance_dir().join("ga4gh-beacon-v2")
}

fn model_schemas_dir() -> PathBuf {
    conformance_dir().join("ga4gh-beacon-v2-default-model")
}

fn vrs_schema_dir() -> PathBuf {
    conformance_dir().join("ga4gh-vrs-1.3")
}

/// The vendored file count a set's `VENDORED.md` declares, so this test and
/// `scripts/vendored.sh verify` agree about how many schemas exist without a second
/// hard-coded number to drift.
fn declared_file_count(dir: &Path) -> usize {
    let md = std::fs::read_to_string(dir.join("VENDORED.md"))
        .unwrap_or_else(|e| panic!("{} carries a VENDORED.md: {e}", dir.display()));
    // `- **Files:** `36``
    let line = md
        .lines()
        .find(|l| l.contains("**Files:**"))
        .unwrap_or_else(|| panic!("{}/VENDORED.md declares a **Files:** count", dir.display()));
    line.split('`')
        .nth(1)
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("cannot parse a file count out of {line:?}"))
}

/// Load one vendored set into `map`, keyed by `base` + `<relative path>`, and return how
/// many documents it contributed.
///
/// The count is asserted against the set's own `VENDORED.md` `**Files:**` field, exactly and
/// not as a floor. A missing schema does not fail loudly; it just means fewer things get
/// validated. A `$ref` resolution failure is fatal, but only for refs a still-loaded schema
/// makes, and a root schema that vanished is never asked for.
fn load_set(dir: &Path, base: &str, map: &mut HashMap<String, Value>) -> usize {
    let before = map.len();
    collect_json(dir, dir, base, map);
    let loaded = map.len() - before;
    let expected = declared_file_count(dir);
    assert_eq!(
        loaded,
        expected,
        "vendored set {} holds {loaded} schema(s) but its VENDORED.md declares {expected} — \
         re-vendor incomplete, or a schema was deleted",
        dir.display()
    );
    loaded
}

/// Load every vendored schema — the Beacon framework, the Beacon default model, and VRS
/// 1.3 — into one retriever map.
///
/// The framework set is loaded twice, under [`BASE`] and under [`UPSTREAM_FRAMEWORK_BASE`].
/// The framework's own cross-file refs are relative and resolve under either, while the
/// default model refs framework files by absolute upstream URL, which resolves only under the
/// second. Same bytes, two names.
fn load_schemas() -> Arc<HashMap<String, Value>> {
    let mut map = HashMap::new();
    // Each `load_set` asserts that the files it added to the map equal the count its
    // `VENDORED.md` declares, so a key collision between two sets, meaning a base URI that is
    // not unique, fails there as a short set. Summing the returns and comparing to
    // `map.len()` here would telescope by construction and could not fail for any input.
    load_set(&schemas_dir(), BASE, &mut map);
    load_set(&schemas_dir(), UPSTREAM_FRAMEWORK_BASE, &mut map);
    load_set(&model_schemas_dir(), MODEL_BASE, &mut map);
    load_set(&vrs_schema_dir(), VRS_BASE, &mut map);
    Arc::new(map)
}

fn collect_json(root: &Path, dir: &Path, base: &str, map: &mut HashMap<String, Value>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_json(root, &path, base, map);
        } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            map.insert(format!("{base}{rel}"), value);
        }
    }
}

/// Build a validator for one framework response schema (a path relative to [`BASE`]).
fn validator_for(relpath: &str, schemas: &Arc<HashMap<String, Value>>) -> Validator {
    validator_for_uri(&format!("{BASE}{relpath}"), schemas)
}

/// Build a validator for the vendored schema served at `key`, injecting its `$id` so the
/// relative refs in the document resolve against its vendored location.
fn validator_for_uri(key: &str, schemas: &Arc<HashMap<String, Value>>) -> Validator {
    let mut schema = schemas
        .get(key)
        .unwrap_or_else(|| panic!("vendored root schema {key} present"))
        .clone();
    schema
        .as_object_mut()
        .expect("a response schema is a JSON object")
        .insert("$id".to_owned(), Value::String(key.to_owned()));
    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .with_retriever(Ga4ghRetriever {
            schemas: Arc::clone(schemas),
        })
        .build(&schema)
        .expect("the vendored GA4GH schema graph builds")
}

/// Assert `body` conforms to `validator`, surfacing every validation error.
fn assert_conforms(validator: &Validator, body: &Value, what: &str) {
    let errors: Vec<String> = validator.iter_errors(body).map(|e| e.to_string()).collect();
    assert!(
        errors.is_empty(),
        "{what} does not conform to its GA4GH v2.2.0 schema:\n{}",
        errors.join("\n")
    );
}

// ===================== node state + drivers =====================

/// A fixed service config with every optional `[beacon]`/`[beacon.organization]`
/// field set, so the informational responses exercise the full key set (mirrors
/// `beacon_info.rs`'s golden config).
fn info_state() -> AppState {
    let toml = r#"
[service]
base_url = "https://beacon.example.org"
data_dir = "/tmp/gdi-node-standalone-schema-conformance"

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "/beacon/v2"
id = "org.example.beacon"
name = "Example GDI Beacon"
api_version = "v2.2.0"
environment = "test"
documentation_url = "https://beacon.example.org/docs"
description = "An example aggregated allele-frequency beacon."
version = "1.2.3"
alternative_url = "https://alt.example.org/beacon"
created_at = "2026-01-01T00:00:00Z"
updated_at = "2026-06-16T00:00:00Z"

[beacon.organization]
id = "org.example"
name = "Example Organization"
welcome_url = "https://example.org"
contact_url = "mailto:beacon@example.org"
description = "The example organization."
logo_url = "https://example.org/logo.png"
"#;
    let cfg = ServiceConfig::from_toml_str(toml).unwrap();
    AppState::new(cfg, StatusIndex::new(), NodeIdentities::empty())
}

// A standalone test target cannot import `tests/it/fixtures`, so this stays local.
/// A representative valid manifest for the COVID dataset (dataset floor 0).
fn manifest_for(id: &str, number_of_records: u64) -> Manifest {
    Manifest {
        payload: None,
        metadata: ManifestMetadata {
            dataset_id: id.to_owned(),
            catalog: CATALOG.to_owned(),
            title: LocalizedText::Plain("COVID monogenic AFs".to_owned()),
            description: Some(LocalizedText::Plain(
                "Aggregated allele frequencies for COVID monogenic variants.".to_owned(),
            )),
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

/// An `AppState` with the COVID dataset ingested + visible, served at floor 0 (so
/// the only variant is a hit). Returns the `TempDir` so the data dir outlives queries.
fn covid_state() -> (AppState, tempfile::TempDir) {
    covid_state_inner(None)
}

/// The same fixture, but with the sensitive mount at the same prefix as the aggregated one,
/// which makes the router `MountScope::Combined` and advertises all three entry types.
///
/// `covid_state` sets only `aggregated_base_path`, so its mounts split and `/beacon/v2/map`
/// is `MountScope::Aggregated`. Only a combined mount advertises `individual`, so this state
/// is what brings the third GA4GH entry type inside the wire-conformance gate.
fn covid_state_combined() -> (AppState, tempfile::TempDir) {
    covid_state_inner(Some(BEACON_PREFIX))
}

fn covid_state_inner(sensitive_base_path: Option<&str>) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let staging = tmp.path().join(format!("staging-{DATASET_ID}"));
    std::fs::create_dir_all(&staging).unwrap();
    let vcf = test_util::covid_vcf_path();
    let out = convert_vcf(
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
        serde_json::to_vec_pretty(&manifest_for(DATASET_ID, out.number_of_records)).unwrap(),
    )
    .unwrap();

    let mut catalogs = std::collections::BTreeMap::new();
    catalogs.insert(
        CATALOG.to_owned(),
        "Genome of Europe Aggregated Data".to_owned(),
    );
    let ok = ingest_staging_dir(
        &staging,
        &data_dir,
        &ParquetCaps::default(),
        &catalogs,
        &DatasetEncryptor::plaintext(),
    )
    .unwrap();

    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "/beacon/v2"
{sensitive}
id = "org.test.beacon"
name = "Test Beacon"
environment = "test"
min_allele_count = 0

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#,
        data_dir.display(),
        sensitive = sensitive_base_path
            .map(|p| format!("sensitive_base_path = \"{p}\""))
            .unwrap_or_default(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();

    let state = AppState::new(cfg, StatusIndex::new(), NodeIdentities::empty());
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        DatasetEntry {
            id: ok.id,
            metadata: ok.metadata,
            config: ok.config,
            state: DatasetState::Visible,
            metadata_modified: None,
        },
    );
    (state, tmp)
}

async fn get_json(state: AppState, uri: &str) -> (StatusCode, Value) {
    let router = build_router(state);
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn post_g_variants(state: AppState, params: Value) -> (StatusCode, Value) {
    let router = build_router(state);
    let body = serde_json::json!({ "query": { "requestParameters": params } });
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// The path (+ any query) of an absolute `rootUrl`, stripping `scheme://host` — the
/// node advertises `/map` `rootUrl`s against its configured `base_url`, but the
/// in-process router is driven by path only.
fn url_path(url: &str) -> &str {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    match after_scheme.find('/') {
        Some(i) => &after_scheme[i..],
        None => "/",
    }
}

/// A `g_variants` query for the known COVID site (chr3:45823240 T>C, a hit at floor 0).
fn hit_params(granularity: &str) -> Value {
    serde_json::json!({
        "referenceName": "3",
        "start": [45_823_239],
        "referenceBases": "T",
        "alternateBases": "C",
        "assemblyId": "GRCh38",
        "requestedGranularity": granularity
    })
}

// ===================== tests =====================

#[tokio::test]
async fn info_response_conforms_to_ga4gh_schema() {
    let schemas = load_schemas();
    let validator = validator_for("responses/beaconInfoResponse.json", &schemas);
    let (status, body) = get_json(info_state(), "/beacon/v2/info").await;
    assert_eq!(status, StatusCode::OK);
    assert_conforms(&validator, &body, "/info");
}

#[tokio::test]
async fn configuration_response_conforms_to_ga4gh_schema() {
    let schemas = load_schemas();
    let validator = validator_for("responses/beaconConfigurationResponse.json", &schemas);
    let (status, body) = get_json(info_state(), "/beacon/v2/configuration").await;
    assert_eq!(status, StatusCode::OK);
    assert_conforms(&validator, &body, "/configuration");
}

#[tokio::test]
async fn g_variants_record_hit_conforms_to_resultsets_schema() {
    let schemas = load_schemas();
    let validator = validator_for("responses/beaconResultsetsResponse.json", &schemas);
    let (state, _tmp) = covid_state();
    let (status, body) = post_g_variants(state, hit_params("record")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["responseSummary"]["exists"], true,
        "the COVID variant is a hit at floor 0"
    );
    assert_conforms(&validator, &body, "g_variants record hit");
}

/// A query that omits `assemblyId` on a single-assembly node is answered with the assumed
/// assembly, and that response — carrying the extra
/// `meta.receivedRequestSummary.assumedAssemblyId` key — still conforms.
///
/// The wire half of the assembly policy: the extra key must not take the envelope out of
/// conformance.
#[tokio::test]
async fn assumed_assembly_response_conforms_to_resultsets_schema() {
    let schemas = load_schemas();
    let validator = validator_for("responses/beaconResultsetsResponse.json", &schemas);
    let (state, _tmp) = covid_state();
    let mut params = hit_params("record");
    params
        .as_object_mut()
        .expect("hit_params is an object")
        .remove("assemblyId");
    let (status, body) = post_g_variants(state, params).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["meta"]["receivedRequestSummary"]["assumedAssemblyId"], "GRCh38",
        "the assumed assembly must be echoed: {body}"
    );
    assert_conforms(&validator, &body, "g_variants with an assumed assembly");
}

/// The assumed assembly is not echoed under the standard `requestParameters` key. The
/// vendored framework's `requests/requestParameters.json` is a placeholder that types every
/// entry as `{"type": "object"}`, so a scalar echo would make the node's own conformance gate
/// reject its own response.
///
/// The placeholder is not obviously right: upstream's `beacon-v2-default-model` types
/// `genomicVariations.assemblyId` as a string, contradicting the model it defers to. If a
/// re-vendor makes this test pass, the echo belongs back under `requestParameters` and
/// `ReceivedRequestSummary::assumed_assembly_id` can go.
#[tokio::test]
async fn framework_request_parameters_placeholder_rejects_a_scalar_echo() {
    let schemas = load_schemas();
    let validator = validator_for("responses/beaconResultsetsResponse.json", &schemas);
    let (state, _tmp) = covid_state();
    let (status, body) = post_g_variants(state, hit_params("record")).await;
    assert_eq!(status, StatusCode::OK);
    assert_conforms(&validator, &body, "baseline g_variants record hit");

    let mut echoed = body.clone();
    echoed["meta"]["receivedRequestSummary"]["requestParameters"] =
        serde_json::json!({ "assemblyId": "GRCh38" });
    assert!(
        validator.iter_errors(&echoed).next().is_some(),
        "the framework placeholder ACCEPTED a scalar `requestParameters` entry — re-read \
         `requests/requestParameters.json` and move the assumed-assembly echo back to the \
         standard key.\nbody: {echoed}"
    );
}

/// Build a validator for the default-model `genomicVariations` entity schema.
fn genomic_variations_validator(schemas: &Arc<HashMap<String, Value>>) -> Validator {
    validator_for_uri(&format!("{MODEL_BASE}{GENOMIC_VARIATIONS_SCHEMA}"), schemas)
}

/// Collect every `results[]` item of a `g_variants` record response, asserting there is at
/// least one at every level.
///
/// The emptiness assertions are the point: every caller's real subject is derived from
/// this body, and a derived subject that comes back empty makes the loop below run zero
/// times — a test that cannot fail. `resultSets`, its `results`, and the flattened total
/// are each checked so a shrink at any level is loud.
fn record_results(body: &Value) -> Vec<Value> {
    let sets = body["response"]["resultSets"]
        .as_array()
        .expect("a record response carries response.resultSets");
    assert!(
        !sets.is_empty(),
        "no resultSets in the record response — nothing to validate"
    );
    let mut items = Vec::new();
    for (i, set) in sets.iter().enumerate() {
        let results = set["results"]
            .as_array()
            .unwrap_or_else(|| panic!("resultSets[{i}] carries a results array"));
        assert!(
            !results.is_empty(),
            "resultSets[{i}].results is empty — nothing to validate"
        );
        items.extend(results.iter().cloned());
    }
    assert!(!items.is_empty(), "no results[] items to validate");
    items
}

/// Every `results[]` item of a real `/g_variants` record response must validate
/// against the vendored default-model `genomicVariations` schema — the schema the node's
/// own `meta.returnedSchemas[].schema` URL names.
///
/// This is the payload half of the gate. `beaconResultsetsResponse` constrains `results` as
/// `{"type": "array", "items": {"type": "object"}}`, so it accepts any object there. A
/// `variation.location` matching no VRS 1.3 class, with bare integer `interval.start` and
/// `interval.end` and no `type` on the location or the interval, keeps every envelope
/// assertion green while a generated client fails to deserialise it. Consumers on the
/// allele-frequency network expect the VRS shape.
#[tokio::test]
async fn g_variants_results_conform_to_the_default_model_schema() {
    let schemas = load_schemas();
    let validator = genomic_variations_validator(&schemas);
    let (state, _tmp) = covid_state();
    let (status, body) = post_g_variants(state, hit_params("record")).await;
    assert_eq!(status, StatusCode::OK);
    for (i, item) in record_results(&body).iter().enumerate() {
        assert_conforms(&validator, item, &format!("g_variants results[{i}]"));
    }
}

/// The default-model and VRS schema graph rejects the pre-VRS `variation` shape, and each of
/// the three tags separately.
///
/// Without this, the test above is positive-only over live output. Replacing the vendored
/// default model with `{}`, dropping the `oneOf` under `variation`, or deleting
/// `additionalProperties: false` from VRS `SequenceLocation` is strictly more permissive, so
/// it would keep passing while validating nothing, at an unchanged file count and, if the
/// edit is upstream-shaped, past `scripts/vendored.sh verify` too. Each case here is a shape
/// the node could regress to.
#[tokio::test]
async fn default_model_schema_rejects_the_pre_vrs_variation_shape() {
    let schemas = load_schemas();
    let validator = genomic_variations_validator(&schemas);
    let (state, _tmp) = covid_state();
    let (status, body) = post_g_variants(state, hit_params("record")).await;
    assert_eq!(status, StatusCode::OK);
    let good = record_results(&body)
        .into_iter()
        .next()
        .expect("record_results asserts at least one item");
    assert_conforms(&validator, &good, "baseline g_variants results[0]");

    let cases: [Perturbation; 4] = [
        // The pre-VRS 1.3 shape: untyped location, untyped interval, bare-integer
        // coordinates.
        ("the whole pre-VRS location", |v| {
            let location = v["variation"]["location"].clone();
            v["variation"]["location"] = serde_json::json!({
                "interval": {
                    "start": location["interval"]["start"]["value"].clone(),
                    "end": location["interval"]["end"]["value"].clone(),
                },
                "sequence_id": location["sequence_id"].clone(),
            });
        }),
        ("drop `location.type`", |v| {
            v["variation"]["location"]
                .as_object_mut()
                .expect("location object")
                .remove("type");
        }),
        ("drop `location.interval.type`", |v| {
            v["variation"]["location"]["interval"]
                .as_object_mut()
                .expect("interval object")
                .remove("type");
        }),
        ("bare-integer `interval.start`", |v| {
            let start = v["variation"]["location"]["interval"]["start"]["value"].clone();
            v["variation"]["location"]["interval"]["start"] = start;
        }),
    ];

    for (what, perturb) in cases {
        let mut bad = good.clone();
        perturb(&mut bad);
        assert_ne!(bad, good, "{what}: perturbation changed nothing");
        assert!(
            validator.iter_errors(&bad).next().is_some(),
            "{what}: the vendored default-model schema ACCEPTED it. VRS 1.3 requires `type` \
             on SequenceLocation and SequenceInterval and an object coordinate, so the \
             schema graph is not constraining anything — a `required`/`oneOf` was lost, or \
             a $ref silently resolved to something permissive.\nbody: {bad}"
        );
    }
}

#[tokio::test]
async fn returned_schemas_use_spec_entity_type_field() {
    // Guard the Beacon v2.2.0 `SchemasPerEntity` field name on a served response. The
    // vendored schema declares no `required` and no `additionalProperties: false`, so a wrong
    // field name such as `entryType` would still schema-validate. This asserts the exact key.
    let (state, _tmp) = covid_state();
    let (status, body) = post_g_variants(state, hit_params("record")).await;
    assert_eq!(status, StatusCode::OK);
    let schema0 = &body["meta"]["returnedSchemas"][0];
    assert!(
        schema0.get("entityType").is_some(),
        "returnedSchemas item must use the spec `entityType` key, got {schema0}"
    );
    assert!(
        schema0.get("entryType").is_none(),
        "returnedSchemas item must NOT emit the non-spec `entryType` key"
    );
}

#[tokio::test]
async fn granularity_shaping_is_pinned() {
    // The vendored response schemas leave the `responseSummary`/`response` shape loose
    // (`numTotalResults` is optional; `response` is optional), so passing them does not
    // prove the node's disclosure contract. Pin the actual per-granularity shape so a
    // regression (e.g. leaking a count into a boolean response) is caught by the gate.
    let (state, _tmp) = covid_state();

    // boolean: `exists` only — the count is withheld, and no record-level body.
    let (_s, b) = post_g_variants(state.clone(), hit_params("boolean")).await;
    assert_eq!(b["meta"]["returnedGranularity"], "boolean");
    assert_eq!(b["responseSummary"]["exists"], true);
    assert!(
        b["responseSummary"].get("numTotalResults").is_none(),
        "boolean must withhold numTotalResults, got {}",
        b["responseSummary"]
    );
    assert!(
        b.get("response").is_none(),
        "boolean must carry no record-level `response` member"
    );

    // count: `exists` + `numTotalResults`, but still no record-level body.
    let (_s, c) = post_g_variants(state.clone(), hit_params("count")).await;
    assert_eq!(c["meta"]["returnedGranularity"], "count");
    assert_eq!(c["responseSummary"]["exists"], true);
    assert_eq!(c["responseSummary"]["numTotalResults"], 1);
    assert!(
        c.get("response").is_none(),
        "count must carry no record-level `response` member"
    );

    // record: `exists` + `numTotalResults` + populated resultSets.
    let (_s, r) = post_g_variants(state, hit_params("record")).await;
    assert_eq!(r["meta"]["returnedGranularity"], "record");
    assert_eq!(r["responseSummary"]["numTotalResults"], 1);
    assert!(
        r["response"]["resultSets"][0]["results"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "record must serve resultSets[].results"
    );
}

/// One schema perturbation: a label, and the edit that removes a required member.
type Perturbation = (&'static str, fn(&mut Value));

/// Every vendored root response schema rejects a body missing one of its own declared
/// `required` members.
///
/// `vendored_schemas_reject_malformed_bodies` below proves this in depth for one schema; this
/// proves it in breadth for all ten, so "the vendored tree still constrains things" is a
/// statement about the tree rather than about one file. Between them, a re-vendor to a weaker
/// upstream or an edit that strips `required` arrays cannot pass.
///
/// The member list is read out of each schema rather than hard-coded, so the test adapts to a
/// re-vendor. It asserts the list is non-empty first, because a schema that declares nothing
/// required would otherwise pass by having no cases to run.
#[tokio::test]
async fn every_root_schema_enforces_its_required_members() {
    let schemas = load_schemas();
    let (state, _tmp) = covid_state();
    let info = info_state();

    // One real, served body per root response schema.
    let bodies: Vec<(&str, Value)> = vec![
        (
            "responses/beaconInfoResponse.json",
            get_json(info.clone(), "/beacon/v2/info").await.1,
        ),
        (
            "responses/beaconConfigurationResponse.json",
            get_json(info.clone(), "/beacon/v2/configuration").await.1,
        ),
        (
            "responses/beaconEntryTypesResponse.json",
            get_json(info.clone(), "/beacon/v2/entry_types").await.1,
        ),
        (
            "responses/beaconFilteringTermsResponse.json",
            get_json(info, "/beacon/v2/filtering_terms").await.1,
        ),
        (
            "responses/beaconMapResponse.json",
            get_json(state.clone(), &format!("{BEACON_PREFIX}/map"))
                .await
                .1,
        ),
        (
            "responses/beaconCollectionsResponse.json",
            get_json(
                state.clone(),
                &format!("{BEACON_PREFIX}/datasets?requestedGranularity=record"),
            )
            .await
            .1,
        ),
        (
            "responses/beaconResultsetsResponse.json",
            post_g_variants(state.clone(), hit_params("record")).await.1,
        ),
        (
            "responses/beaconCountResponse.json",
            post_g_variants(state.clone(), hit_params("count")).await.1,
        ),
        (
            "responses/beaconBooleanResponse.json",
            post_g_variants(state.clone(), hit_params("boolean"))
                .await
                .1,
        ),
        (
            "responses/beaconErrorResponse.json",
            // `geneId` is unsupported -> 400 rendered as a beaconErrorResponse.
            post_g_variants(
                state,
                serde_json::json!({
                    "referenceName": "3",
                    "start": [45_823_239],
                    "end": [45_823_300],
                    "geneId": "BRCA1"
                }),
            )
            .await
            .1,
        ),
    ];

    for (relpath, good) in bodies {
        let validator = validator_for(relpath, &schemas);
        assert_conforms(&validator, &good, relpath);

        let required: Vec<String> = schemas[&format!("{BASE}{relpath}")]["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{relpath} declares no top-level `required` array"))
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect();
        assert!(
            !required.is_empty(),
            "{relpath} declares an EMPTY `required` array — it constrains nothing, and this \
             test would silently have no cases to run"
        );

        for member in required {
            let mut bad = good.clone();
            let removed = bad
                .as_object_mut()
                .expect("a response body is a JSON object")
                .remove(&member);
            assert!(
                removed.is_some(),
                "{relpath}: the real body has no `{member}`, yet the schema requires it — \
                 the node is not serving a member its own vendored schema mandates"
            );
            assert!(
                validator.iter_errors(&bad).next().is_some(),
                "{relpath}: the schema ACCEPTED a body with required member `{member}` \
                 removed. Its `required` array is not being enforced — the array was lost, \
                 or the $ref chain resolved to something permissive."
            );
        }
    }
}

/// The vendored schemas reject a malformed body, rather than merely accepting a well-formed
/// one.
///
/// The other tests in this file are positive-only, which makes schema damage invisible.
/// Replacing a vendored schema with `{}`, or deleting one of its `required` arrays, is
/// strictly more permissive, so every positive assertion still passes and the file count does
/// not move. `scripts/vendored.sh verify` checksums the tree and so catches tampering; this
/// catches the schemas being toothless for any other reason, including a re-vendor to a
/// weaker upstream.
///
/// Same idea as `conformance/check_fdp_negative.py` on the SHACL side: perturb a known-good
/// body and require a complaint.
#[tokio::test]
async fn vendored_schemas_reject_malformed_bodies() {
    let schemas = load_schemas();
    let (state, _tmp) = covid_state();
    let validator = validator_for("responses/beaconResultsetsResponse.json", &schemas);

    let (status, good) = post_g_variants(state, hit_params("record")).await;
    assert_eq!(status, StatusCode::OK);
    assert_conforms(&validator, &good, "baseline g_variants record");

    // Each perturbation removes exactly one thing the schema graph requires, at a different
    // depth: a top-level member, a nested `meta` member, and a required key inside a
    // `resultSets[]` item. A schema that has lost its `required` arrays passes all three.
    let cases: [Perturbation; 3] = [
        ("drop top-level `meta`", |v| {
            v.as_object_mut().expect("object").remove("meta");
        }),
        ("drop `meta.receivedRequestSummary`", |v| {
            v["meta"]
                .as_object_mut()
                .expect("meta object")
                .remove("receivedRequestSummary");
        }),
        ("drop `resultSets[0].setType`", |v| {
            v["response"]["resultSets"][0]
                .as_object_mut()
                .expect("resultSet object")
                .remove("setType");
        }),
    ];

    for (what, perturb) in cases {
        let mut bad = good.clone();
        perturb(&mut bad);
        assert_ne!(bad, good, "{what}: perturbation changed nothing");
        let errors: Vec<String> = validator.iter_errors(&bad).map(|e| e.to_string()).collect();
        assert!(
            !errors.is_empty(),
            "{what}: the vendored beaconResultsetsResponse schema ACCEPTED a body missing a \
             required member. The schema graph is not constraining anything — a `required` \
             array was lost, or the $ref chain silently resolved to something permissive."
        );
    }
}

#[tokio::test]
async fn record_result_set_carries_the_userportal_key_set() {
    // Consumers read `resultSets[].beaconId` and `id`, and the vendored `beaconResultset`
    // schema does not require either, so the exact key set is pinned here. A field removal,
    // such as dropping `beaconId` or renaming `resultsCount`, is then caught.
    // `gdiDatasetInfo` is the namespaced disclosure extension carrying assembly, effective
    // floor and populations, which makes a `0` self-describing.
    let (state, _tmp) = covid_state();
    let (status, body) = post_g_variants(state, hit_params("record")).await;
    assert_eq!(status, StatusCode::OK);
    let obj = body["response"]["resultSets"][0]
        .as_object()
        .expect("resultSet[0] is a JSON object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "beaconId",
            "exists",
            "gdiDatasetInfo",
            "id",
            "results",
            "resultsCount",
            "setType"
        ],
        "resultSet key set drifted (consumers read beaconId and id)"
    );
}

#[tokio::test]
async fn g_variants_all_returns_miss_with_disclosure_for_absent_variant() {
    // Null disclosure over the real HTTP stack: a query for an absent variant with
    // `includeResultsetResponses=ALL` names the considered dataset as an `exists: false` miss
    // carrying `gdiDatasetInfo`, so a client can bound the `0` without a second call to
    // `/datasets`. Under the default `HIT` the miss stays hidden, which the
    // membership-inference guards cover.
    let (state, _tmp) = covid_state();
    let params = serde_json::json!({
        "referenceName": "3",
        "start": [1], // no variant at chr3:1 in the fixture
        "referenceBases": "T",
        "alternateBases": "C",
        "assemblyId": "GRCh38",
        "requestedGranularity": "record",
        "includeResultsetResponses": "ALL",
    });
    let (status, body) = post_g_variants(state, params).await;
    assert_eq!(status, StatusCode::OK);
    // Truthful negative overall.
    assert_eq!(body["responseSummary"]["exists"], false);
    // ...but the considered dataset is named as an exists:false miss...
    let sets = body["response"]["resultSets"]
        .as_array()
        .expect("resultSets array");
    assert_eq!(
        sets.len(),
        1,
        "ALL names the considered dataset even on a miss"
    );
    assert_eq!(sets[0]["exists"], false);
    assert_eq!(sets[0]["resultsCount"], 0);
    // ...carrying the disclosure that makes the 0 interpretable (floor + assembly).
    assert_eq!(sets[0]["gdiDatasetInfo"]["assembly"], "GRCh38");
    assert_eq!(sets[0]["gdiDatasetInfo"]["minAlleleCount"], 0);
}

#[tokio::test]
async fn g_variants_count_conforms_to_count_schema() {
    let schemas = load_schemas();
    let validator = validator_for("responses/beaconCountResponse.json", &schemas);
    let (state, _tmp) = covid_state();
    let (status, body) = post_g_variants(state, hit_params("count")).await;
    assert_eq!(status, StatusCode::OK);
    assert_conforms(&validator, &body, "g_variants count");
}

#[tokio::test]
async fn g_variants_boolean_conforms_to_boolean_schema() {
    let schemas = load_schemas();
    let validator = validator_for("responses/beaconBooleanResponse.json", &schemas);
    let (state, _tmp) = covid_state();
    let (status, body) = post_g_variants(state, hit_params("boolean")).await;
    assert_eq!(status, StatusCode::OK);
    assert_conforms(&validator, &body, "g_variants boolean");
}

#[tokio::test]
async fn error_response_conforms_to_ga4gh_schema() {
    let schemas = load_schemas();
    let validator = validator_for("responses/beaconErrorResponse.json", &schemas);
    let (state, _tmp) = covid_state();
    // A `geneId` parameter is unsupported -> 400 rendered as a `beaconErrorResponse`.
    let (status, body) = post_g_variants(
        state,
        serde_json::json!({
            "referenceName": "3",
            "start": [45_823_239],
            "end": [45_823_300],
            "geneId": "BRCA1"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_conforms(&validator, &body, "beaconErrorResponse");
}

#[tokio::test]
async fn service_info_conforms_to_ga4gh_service_info_schema() {
    let schemas = load_schemas();
    // `/service-info` is the bare GA4GH ServiceInfo (not a beacon-framework wrapper),
    // crawled by the GA4GH service registry — validate it against the vendored
    // service-info schema directly.
    let validator = validator_for("responses/ga4gh-service-info-1-0-0-schema.json", &schemas);
    let (status, body) = get_json(info_state(), "/beacon/v2/service-info").await;
    assert_eq!(status, StatusCode::OK);
    assert_conforms(&validator, &body, "/service-info");
}

#[tokio::test]
async fn entry_types_conforms_to_ga4gh_schema() {
    let schemas = load_schemas();
    let validator = validator_for("responses/beaconEntryTypesResponse.json", &schemas);
    let (status, body) = get_json(info_state(), "/beacon/v2/entry_types").await;
    assert_eq!(status, StatusCode::OK);
    assert_conforms(&validator, &body, "/entry_types");
}

#[tokio::test]
async fn filtering_terms_conforms_to_ga4gh_schema() {
    let schemas = load_schemas();
    let validator = validator_for("responses/beaconFilteringTermsResponse.json", &schemas);
    let (status, body) = get_json(info_state(), "/beacon/v2/filtering_terms").await;
    assert_eq!(status, StatusCode::OK);
    assert_conforms(&validator, &body, "/filtering_terms");
}

/// Discovery crawl: validate `/map`, then GET every endpoint it advertises and validate each
/// response against the schema for its entry type. This is the producer-side analog of an
/// external GA4GH crawler, in-process and hermetic. It forces `record` granularity so each
/// endpoint returns its full record shape, with `response` present, which makes the entry
/// type to schema mapping exact.
#[tokio::test]
async fn map_advertised_endpoints_all_conform() {
    let (state, _tmp) = covid_state();
    let served = crawl_and_validate_map(state).await;
    // Pin which entry types this mount covered, not merely that some did. An aggregated
    // mount serves these two; `individual` needs a combined mount and is covered below.
    assert_eq!(
        served,
        vec!["dataset".to_owned(), "genomicVariant".to_owned()],
        "aggregated mount advertised/served an unexpected entry-type set"
    );
}

/// The same crawl on a combined mount, which is the only layout that advertises the
/// `individual` entry type and so the only one that exercises the `"individual"` arm of
/// `crawl_and_validate_map`.
#[tokio::test]
async fn map_advertised_endpoints_all_conform_on_a_combined_mount() {
    let (state, _tmp) = covid_state_combined();
    let served = crawl_and_validate_map(state).await;
    assert_eq!(
        served,
        vec![
            "dataset".to_owned(),
            "genomicVariant".to_owned(),
            "individual".to_owned()
        ],
        "combined mount must advertise and serve all three GA4GH entry types"
    );
}

/// Crawl `/map` on `state`, GET every advertised endpoint, validate each body against the
/// schema for its entry type, and return the sorted entry types that served.
async fn crawl_and_validate_map(state: AppState) -> Vec<String> {
    let schemas = load_schemas();

    // 1. /map itself.
    let map_validator = validator_for("responses/beaconMapResponse.json", &schemas);
    let (status, map) = get_json(state.clone(), &format!("{BEACON_PREFIX}/map")).await;
    assert_eq!(status, StatusCode::OK);
    assert_conforms(&map_validator, &map, "/map");

    // 2. Every advertised endpoint set -> GET its rootUrl, validate by entry type.
    let resultsets = validator_for("responses/beaconResultsetsResponse.json", &schemas);
    let collections = validator_for("responses/beaconCollectionsResponse.json", &schemas);
    let error = validator_for("responses/beaconErrorResponse.json", &schemas);

    let sets = map["response"]["endpointSets"]
        .as_object()
        .expect("/map advertises an endpointSets object");
    assert!(
        !sets.is_empty(),
        "/map advertises at least one endpoint set"
    );

    // Count how many advertised endpoints served. Without this the test tolerates the whole
    // advertised surface being dead: a non-200 is validated against the error schema, which a
    // well-formed error satisfies, so "all conform" would hold with nothing being served. The
    // fixture state carries a real COVID dataset, so the dataset and genomicVariant sets must
    // answer.
    let mut served: Vec<String> = Vec::new();
    let mut refused: Vec<String> = Vec::new();

    for (name, set) in sets {
        let entry_type = set["entryType"].as_str().unwrap_or(name);
        let path = url_path(set["rootUrl"].as_str().expect("rootUrl is a string"));
        let (status, body) = get_json(
            state.clone(),
            &format!("{path}?requestedGranularity=record"),
        )
        .await;

        // record granularity at a served entry type -> 200 with the full record
        // shape; anything else must still be a valid beaconErrorResponse envelope.
        if status == StatusCode::OK {
            let success = match entry_type {
                "dataset" => &collections,
                "genomicVariant" | "individual" => &resultsets,
                other => panic!("unmapped advertised entry type {other:?} at {path}"),
            };
            assert_conforms(success, &body, &format!("GET {path} ({entry_type})"));
            served.push(entry_type.to_owned());
        } else {
            assert_conforms(&error, &body, &format!("GET {path} -> {status}"));
            refused.push(format!("{entry_type} at {path} -> {status}"));
        }
    }

    // `served > 0` would be too weak: with a COVID dataset mounted, a `/g_variants`
    // regression to 400 still leaves `served == 1` from `/datasets`. Nothing may refuse.
    assert!(
        refused.is_empty(),
        "advertised endpoint(s) refused to serve: {refused:?}. A non-200 conforms to the \
         error schema, so this test would otherwise pass with part of the advertised \
         surface dead. The fixture state carries a real COVID dataset, so every set /map \
         advertises must answer."
    );
    assert_eq!(
        served.len(),
        sets.len(),
        "served {} of {} advertised endpoint set(s)",
        served.len(),
        sets.len()
    );
    served.sort_unstable();
    served
}
