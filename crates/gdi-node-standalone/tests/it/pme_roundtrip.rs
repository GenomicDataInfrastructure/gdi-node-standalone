//! End-to-end Parquet Modular Encryption round-trip.
//!
//! Drives the real PME write/read seam against a deterministic in-process mock
//! Transit (a wiremock server emulating Vault `transit/datakey` + `decrypt`), so
//! no real Vault is needed:
//!
//! * `datakey/plaintext/<key>` returns a fresh 32-byte key (base64) wrapped as
//!   `vault:v1:<plaintext_b64>` — the wrapped token embeds the plaintext so the
//!   matching `decrypt` is stateless and handles arbitrarily many files.
//! * `decrypt/<key>` parses that suffix back to the plaintext.
//!
//! Tests: the COVID dataset ingested with PME on lands as a `PARE` file and a
//! beacon `scan_dataset` reads back the same frequencies as the plaintext path
//! (`FI_M` ≈ 0.085, Total AC = 618); a mixed plaintext (`PAR1`) + PME (`PARE`) store
//! both read correctly; and a key-mismatch (wrong transit key) is a clear error.
#![cfg(feature = "pme")]
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request as HttpRequest, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::pme::{CachedKeyRetriever, PmeRuntime, VaultDekMinter};
use gdi_node_standalone::state::AppState;
use gdi_node_standalone::vault::VaultClient;
use gdi_node_standalone_beacon::query::{UnboundedRetention, scan_dataset};
use gdi_node_standalone_beacon::request::{Predicates, QueryKind};
use gdi_node_standalone_core::cache::{DatasetEntry, StatusIndex};
use gdi_node_standalone_core::config::{ServiceConfig, VaultConfig};
use gdi_node_standalone_core::ingest::ingest_staging_dir;
use gdi_node_standalone_core::parquet_io::{DatasetDecryptor, DatasetEncryptor};
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use serde_json::Value;
use std::collections::BTreeMap;
use test_util::covid;
use tower::ServiceExt as _; // for `oneshot`
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use crate::fixtures::build_covid_staging_goe;

const MOUNT: &str = "transit";
const KEY: &str = "gdi-at-rest";

/// A stateless mock-Transit `datakey/plaintext` responder: each call mints a fresh
/// 32-byte key (varying by a counter so files get distinct keys) and wraps it as
/// `vault:v1:<plaintext_b64>` so the matching `decrypt` can recover it.
struct DatakeyResponder {
    counter: AtomicU8,
}

impl Respond for DatakeyResponder {
    fn respond(&self, _req: &Request) -> ResponseTemplate {
        let seed = self.counter.fetch_add(1, Ordering::SeqCst);
        // Distinct, deterministic 32-byte key per call.
        let key: Vec<u8> = (0..32u8)
            .map(|i| i.wrapping_add(seed).wrapping_mul(3))
            .collect();
        let plaintext = BASE64.encode(&key);
        let wrapped = format!("vault:v1:{plaintext}");
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "plaintext": plaintext, "ciphertext": wrapped }
        }))
    }
}

/// A stateless mock-Transit `decrypt` responder: recovers the plaintext from the
/// `vault:v1:<plaintext_b64>` wrapped token in the request body.
struct DecryptResponder;

impl Respond for DecryptResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let ct = body
            .get("ciphertext")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let plaintext = ct.strip_prefix("vault:v1:").unwrap_or_default().to_owned();
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({ "data": { "plaintext": plaintext } }))
    }
}

/// Start a mock-Transit server emulating `datakey` + `decrypt`.
async fn mock_transit() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/v1/transit/datakey/plaintext/.*$"))
        .respond_with(DatakeyResponder {
            counter: AtomicU8::new(1),
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/v1/transit/decrypt/.*$"))
        .respond_with(DecryptResponder)
        .mount(&server)
        .await;
    server
}

/// A connected Vault client pointed at the mock-Transit server.
async fn vault_client(address: &str) -> VaultClient {
    VaultClient::connect(&VaultConfig {
        address: address.to_owned(),
        token: Some("hvs.test".to_owned()),
        transit_mount: MOUNT.to_owned(),
        transit_key: Some(KEY.to_owned()),
        ..VaultConfig::default()
    })
    .await
    .expect("connect to mock Transit")
}

/// The node catalog allow-list.
fn node_catalogs() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("gdi-aggregated".to_owned(), "GoE Aggregated".to_owned());
    m
}

/// The first four bytes (file magic) of every `*.parquet` in `dir`.
fn parquet_magics(dir: &Path) -> Vec<[u8; 4]> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name.ends_with(".parquet") {
            let bytes = std::fs::read(&p).unwrap();
            out.push([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
    }
    out
}

/// Assert the COVID chr3:45823239 T>C variant has the canonical frequencies.
fn assert_covid_frequencies(rows: &[gdi_node_standalone_core::parquet_io::AlleleRow]) {
    assert!(!rows.is_empty(), "expected the Total/FI_M rows");
    let total = rows
        .iter()
        .find(|r| r.population == "Total")
        .expect("Total population row");
    assert_eq!(
        total.ac,
        Some(i32::try_from(covid::TOTAL_AC).unwrap()),
        "Total AC must be 618"
    );
    assert_eq!(total.an, Some(i32::try_from(covid::TOTAL_AN).unwrap()));
    let fi_m = rows
        .iter()
        .find(|r| r.population == "FI_M")
        .expect("FI_M population row");
    assert!(
        (f64::from(fi_m.af) - covid::FI_M_AF).abs() < 1e-4,
        "FI_M AF {} not ~ 0.085",
        fi_m.af
    );
    assert_eq!(fi_m.ac, Some(i32::try_from(covid::FI_M_AC).unwrap()));
}

/// The COVID T>C sequence query (chr3, block 4).
fn covid_query() -> QueryKind {
    QueryKind::Sequence {
        pos: 45_823_239,
        ref_: "T".into(),
        alt: "C".into(),
        predicates: Predicates::default(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pme_dataset_round_trips_to_same_frequencies_as_plaintext() {
    let server = mock_transit().await;
    let vault = vault_client(&server.uri()).await;
    let pme = Arc::new(PmeRuntime::new(vault, MOUNT.to_owned(), KEY.to_owned()));

    let tmp = tempfile::tempdir().unwrap();
    let id = "GDI-EE-UTARTU-20260617000000001";
    let staging = build_covid_staging_goe(tmp.path(), id);
    let data_dir = tmp.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();

    // Ingest with PME on (the minter encrypts each parquet at store time).
    let minter: Arc<dyn gdi_node_standalone_core::parquet_io::DekMinter> = pme.minter();
    let encryptor = DatasetEncryptor::with_minter(minter);
    let ok = tokio::task::spawn_blocking({
        let staging = staging.clone();
        let data_dir = data_dir.clone();
        move || {
            ingest_staging_dir(
                &staging,
                &data_dir,
                &ParquetCaps::default(),
                &node_catalogs(),
                &encryptor,
            )
        }
    })
    .await
    .unwrap()
    .expect("PME ingest");
    assert_eq!(ok.id, id);

    // Every stored parquet is PARE (encrypted), not PAR1.
    let published = data_dir.join(id);
    let magics = parquet_magics(&published);
    assert!(!magics.is_empty(), "at least one stored parquet");
    for m in &magics {
        assert_eq!(m, b"PARE", "stored parquet must be PME-encrypted (PARE)");
    }

    // The beacon scan decrypts via the cached retriever and returns the same rows.
    let decryptor = DatasetDecryptor::with_retriever(pme.retriever());
    let rows = tokio::task::spawn_blocking(move || {
        scan_dataset(
            &published,
            "3",
            10_000_000,
            &covid_query(),
            &ParquetCaps::default(),
            &decryptor,
            u64::MAX,
            &mut UnboundedRetention,
        )
    })
    .await
    .unwrap()
    .expect("PME scan");
    assert_covid_frequencies(&rows);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_plaintext_and_pme_store_both_read() {
    let server = mock_transit().await;
    let vault = vault_client(&server.uri()).await;
    let pme = Arc::new(PmeRuntime::new(vault, MOUNT.to_owned(), KEY.to_owned()));

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();

    // One dataset ingested plaintext (PAR1).
    let plain_id = "GDI-EE-UTARTU-20260617000000002";
    let plain_staging = build_covid_staging_goe(tmp.path(), plain_id);
    let plain_dir = data_dir.join(plain_id);
    tokio::task::spawn_blocking({
        let plain_staging = plain_staging.clone();
        let data_dir = data_dir.clone();
        move || {
            ingest_staging_dir(
                &plain_staging,
                &data_dir,
                &ParquetCaps::default(),
                &node_catalogs(),
                &DatasetEncryptor::plaintext(),
            )
        }
    })
    .await
    .unwrap()
    .expect("plaintext ingest");
    for m in parquet_magics(&plain_dir) {
        assert_eq!(&m, b"PAR1", "plaintext dataset must be PAR1");
    }

    // Another dataset ingested PME (PARE).
    let enc_id = "GDI-EE-UTARTU-20260617000000003";
    let enc_staging = build_covid_staging_goe(tmp.path(), enc_id);
    let enc_dir = data_dir.join(enc_id);
    let encryptor = DatasetEncryptor::with_minter(pme.minter());
    tokio::task::spawn_blocking({
        let enc_staging = enc_staging.clone();
        let data_dir = data_dir.clone();
        move || {
            ingest_staging_dir(
                &enc_staging,
                &data_dir,
                &ParquetCaps::default(),
                &node_catalogs(),
                &encryptor,
            )
        }
    })
    .await
    .unwrap()
    .expect("PME ingest");
    for m in parquet_magics(&enc_dir) {
        assert_eq!(&m, b"PARE", "PME dataset must be PARE");
    }

    // One decryptor, carrying a retriever, reads both: `PAR1` ignores it, `PARE` uses it.
    let decryptor = DatasetDecryptor::with_retriever(pme.retriever());
    let dec1 = decryptor.clone();
    let plain_rows = tokio::task::spawn_blocking(move || {
        scan_dataset(
            &plain_dir,
            "3",
            10_000_000,
            &covid_query(),
            &ParquetCaps::default(),
            &dec1,
            u64::MAX,
            &mut UnboundedRetention,
        )
    })
    .await
    .unwrap()
    .expect("plaintext scan with retriever present");
    assert_covid_frequencies(&plain_rows);

    let enc_rows = tokio::task::spawn_blocking(move || {
        scan_dataset(
            &enc_dir,
            "3",
            10_000_000,
            &covid_query(),
            &ParquetCaps::default(),
            &decryptor,
            u64::MAX,
            &mut UnboundedRetention,
        )
    })
    .await
    .unwrap()
    .expect("PME scan");
    assert_covid_frequencies(&enc_rows);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_transit_key_is_a_clear_mismatch_not_opaque_decrypt_fail() {
    let server = mock_transit().await;
    // Mint with KEY...
    let vault = vault_client(&server.uri()).await;
    let minter = VaultDekMinter::new(vault.clone(), MOUNT.to_owned(), KEY.to_owned());

    let tmp = tempfile::tempdir().unwrap();
    let id = "GDI-EE-UTARTU-20260617000000004";
    let staging = build_covid_staging_goe(tmp.path(), id);
    let data_dir = tmp.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();

    let encryptor = DatasetEncryptor::with_minter(Arc::new(minter));
    let published = data_dir.join(id);
    tokio::task::spawn_blocking({
        let staging = staging.clone();
        let data_dir = data_dir.clone();
        move || {
            ingest_staging_dir(
                &staging,
                &data_dir,
                &ParquetCaps::default(),
                &node_catalogs(),
                &encryptor,
            )
        }
    })
    .await
    .unwrap()
    .expect("PME ingest");

    // ...but read with a retriever configured for a different key.
    let retriever = Arc::new(CachedKeyRetriever::new(
        vault,
        MOUNT.to_owned(),
        "a-different-key".to_owned(),
    ));
    let decryptor = DatasetDecryptor::with_retriever(retriever);
    let err = tokio::task::spawn_blocking(move || {
        scan_dataset(
            &published,
            "3",
            10_000_000,
            &covid_query(),
            &ParquetCaps::default(),
            &decryptor,
            u64::MAX,
            &mut UnboundedRetention,
        )
    })
    .await
    .unwrap()
    .expect_err("a wrong transit key must fail the read");
    let msg = format!("{err}");
    assert!(
        msg.contains("key-mismatch"),
        "expected a clear key-mismatch, got: {msg}"
    );
}

/// A service config exposing the aggregated beacon at `/beacon/v2`.
fn service_config(data_dir: &Path) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"

[catalogs]
gdi-aggregated = "GoE Aggregated"

[beacon]
aggregated_base_path = "/beacon/v2"
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).expect("config parses");
    cfg.preflight().expect("config preflight");
    cfg
}

/// A transient Vault *transit* failure while minting a DEK on ingest is a
/// transient `CoreError` — the runtime leaves such datasets for the next reconcile
/// (no quarantine, no permanent error), as the S3/inbox transient paths already do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ingest_transit_datakey_failure_is_transient() {
    // datakey 503 -> VaultError::Transient -> CoreError::Transient at mint time.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/v1/transit/datakey/plaintext/.*$"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let vault = vault_client(&server.uri()).await;
    let pme = Arc::new(PmeRuntime::new(vault, MOUNT.to_owned(), KEY.to_owned()));

    let tmp = tempfile::tempdir().unwrap();
    let id = "GDI-EE-UTARTU-20260618000000001";
    let staging = build_covid_staging_goe(tmp.path(), id);
    let data_dir = tmp.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();

    let encryptor = DatasetEncryptor::with_minter(pme.minter());
    let res = tokio::task::spawn_blocking({
        let staging = staging.clone();
        let data_dir = data_dir.clone();
        move || {
            ingest_staging_dir(
                &staging,
                &data_dir,
                &ParquetCaps::default(),
                &node_catalogs(),
                &encryptor,
            )
        }
    })
    .await
    .unwrap();
    // `Ingested` is not `Debug`, so bind the error directly.
    let Err(err) = res else {
        panic!("a transit datakey failure must error the ingest");
    };
    assert!(
        err.is_transient(),
        "a transit datakey failure must be a TRANSIENT ingest error (re-queue, not quarantine): {err}"
    );
}

/// On an at-rest-encrypted (PARE) dataset, a transit *decrypt* failure during a
/// query is fail-closed: the `g_variants` handler returns a 500 `beaconErrorResponse`
/// — never plaintext rows, never stale-key rows. Ingest succeeds (datakey up);
/// decrypt always 503s; the first query forces a cold-cache transit decrypt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_transit_decrypt_failure_is_500_not_plaintext() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/v1/transit/datakey/plaintext/.*$"))
        .respond_with(DatakeyResponder {
            counter: AtomicU8::new(1),
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/v1/transit/decrypt/.*$"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let vault = vault_client(&server.uri()).await;
    let pme = Arc::new(PmeRuntime::new(vault, MOUNT.to_owned(), KEY.to_owned()));

    let tmp = tempfile::tempdir().unwrap();
    let id = "GDI-EE-UTARTU-20260618000000002";
    let staging = build_covid_staging_goe(tmp.path(), id);
    let data_dir = tmp.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();

    let encryptor = DatasetEncryptor::with_minter(pme.minter());
    let ok = tokio::task::spawn_blocking({
        let staging = staging.clone();
        let data_dir = data_dir.clone();
        move || {
            ingest_staging_dir(
                &staging,
                &data_dir,
                &ParquetCaps::default(),
                &node_catalogs(),
                &encryptor,
            )
        }
    })
    .await
    .unwrap()
    .expect("PME ingest (datakey healthy)");
    for m in parquet_magics(&data_dir.join(id)) {
        assert_eq!(&m, b"PARE", "stored parquet must be PME-encrypted");
    }

    // Build the service with PME active and the dataset visible.
    let state = AppState::new(
        service_config(&data_dir),
        StatusIndex::new(),
        NodeIdentities::empty(),
    )
    .with_pme(Some(pme));
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
    let router = build_router(state);

    let body = serde_json::json!({ "query": { "requestParameters": {
        "referenceName": "3", "start": [45_823_239],
        "referenceBases": "T", "alternateBases": "C",
        "assemblyId": "GRCh38", "requestedGranularity": "RECORD" } } });
    let req = HttpRequest::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a decrypt failure must be a 500, not a partial/plaintext result"
    );
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    // Scrub the random `requestId` before the leak scan: its hex digits can
    // coincidentally contain the count's decimal digits and false-positive the
    // numeric check below (a flaky-test bug, not a real leak).
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let text = crate::fixtures::error_body_without_request_id(&v);
    // Fail-closed: no allele rows / population body may leak on the wire.
    assert!(
        !text.contains("frequencyInPopulations"),
        "no rows may leak on a decrypt failure: {text}"
    );
    assert!(!text.contains("FI_M"), "no population row may leak: {text}");
    assert!(
        !text.contains(&covid::TOTAL_AC.to_string()),
        "no Total AC may leak: {text}"
    );
}

/// A transit *decrypt* that hangs (rather than 503s) during a query must not wedge the
/// request: the Vault client's request timeout fires, the decrypt fails, and the
/// handler is fail-closed (a 500 with no rows) — bounded in time, never hanging and
/// never leaking plaintext.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_hung_transit_decrypt_times_out_fail_closed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/v1/transit/datakey/plaintext/.*$"))
        .respond_with(DatakeyResponder {
            counter: AtomicU8::new(1),
        })
        .mount(&server)
        .await;
    // The decrypt endpoint hangs far longer than the client's request timeout.
    Mock::given(method("POST"))
        .and(path_regex(r"^/v1/transit/decrypt/.*$"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(30)))
        .mount(&server)
        .await;
    // A Vault client with a short request timeout, so the hang is bounded quickly.
    let vault = VaultClient::connect(&VaultConfig {
        address: server.uri(),
        token: Some("hvs.test".to_owned()),
        transit_mount: MOUNT.to_owned(),
        transit_key: Some(KEY.to_owned()),
        request_timeout_seconds: 2,
        ..VaultConfig::default()
    })
    .await
    .expect("connect to mock Transit");
    let pme = Arc::new(PmeRuntime::new(vault, MOUNT.to_owned(), KEY.to_owned()));

    let tmp = tempfile::tempdir().unwrap();
    let id = "GDI-EE-UTARTU-20260706120000014";
    let staging = build_covid_staging_goe(tmp.path(), id);
    let data_dir = tmp.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();

    let encryptor = DatasetEncryptor::with_minter(pme.minter());
    let ok = tokio::task::spawn_blocking({
        let staging = staging.clone();
        let data_dir = data_dir.clone();
        move || {
            ingest_staging_dir(
                &staging,
                &data_dir,
                &ParquetCaps::default(),
                &node_catalogs(),
                &encryptor,
            )
        }
    })
    .await
    .unwrap()
    .expect("PME ingest (datakey healthy)");

    let state = AppState::new(
        service_config(&data_dir),
        StatusIndex::new(),
        NodeIdentities::empty(),
    )
    .with_pme(Some(pme));
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
    let router = build_router(state);

    let body = serde_json::json!({ "query": { "requestParameters": {
        "referenceName": "3", "start": [45_823_239],
        "referenceBases": "T", "alternateBases": "C",
        "assemblyId": "GRCh38", "requestedGranularity": "RECORD" } } });
    let req = HttpRequest::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let started = std::time::Instant::now();
    let resp = router.oneshot(req).await.unwrap();
    let elapsed = started.elapsed();

    // Bounded by the client request timeout of about 2 s, not the 30 s hang.
    assert!(
        elapsed < std::time::Duration::from_secs(15),
        "a hung decrypt must be bounded by the Vault request timeout, not hang: took {elapsed:?}"
    );
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a hung decrypt must fail closed (500), never plaintext"
    );
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let text = crate::fixtures::error_body_without_request_id(&v);
    assert!(
        !text.contains("frequencyInPopulations"),
        "no rows may leak on a hung decrypt: {text}"
    );
    assert!(!text.contains("FI_M"), "no population row may leak: {text}");
    assert!(
        !text.contains(&covid::TOTAL_AC.to_string()),
        "no Total AC may leak: {text}"
    );
}

/// Optional real-server PME round-trip against a live OpenBao / HashiCorp Vault
/// dev with a real `aes256-gcm96` Transit key, `#[ignore]` by default and skipped
/// unless `GDI_TEST_VAULT_ADDR` is set. The mock-Transit tests above are what runs by
/// default; this exercises the genuine `datakey`/`decrypt` wrap against the real
/// engine.
///
/// The maintained route is `scripts/e2e/run-full.sh` (`ci-local.sh e2e-full`): it boots
/// the backends, exports every var below, and sets `GDI_TEST_REQUIRED=1` so a missing
/// one panics instead of skipping to a green. The snippet below is the by-hand route.
///
/// Provision (OpenBao dev):
/// ```text
/// bao secrets enable transit && \
///   bao write -f transit/keys/gdi-at-rest type=aes256-gcm96
/// GDI_TEST_VAULT_ADDR=http://127.0.0.1:8200 GDI_TEST_VAULT_TOKEN=root \
///   cargo test --features pme --test it -- --ignored pme_roundtrip
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a real OpenBao/Vault dev server via GDI_TEST_VAULT_ADDR"]
#[expect(
    clippy::doc_markdown,
    reason = "docs use proper nouns (OpenBao, Vault, HashiCorp) as prose, not code"
)]
async fn real_openbao_pme_round_trip() {
    let Some(addr) = test_util::endpoint_env("GDI_TEST_VAULT_ADDR") else {
        return;
    };
    let token = std::env::var("GDI_TEST_VAULT_TOKEN").unwrap_or_else(|_| "root".to_owned());
    let key = std::env::var("GDI_TEST_TRANSIT_KEY").unwrap_or_else(|_| KEY.to_owned());

    let vault = VaultClient::connect(&VaultConfig {
        address: addr,
        token: Some(token),
        transit_mount: MOUNT.to_owned(),
        transit_key: Some(key.clone()),
        ..VaultConfig::default()
    })
    .await
    .expect("connect to real OpenBao/Vault");
    let pme = Arc::new(PmeRuntime::new(vault, MOUNT.to_owned(), key));

    let tmp = tempfile::tempdir().unwrap();
    let id = "GDI-EE-UTARTU-20260617000000099";
    let staging = build_covid_staging_goe(tmp.path(), id);
    let data_dir = tmp.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();

    let encryptor = DatasetEncryptor::with_minter(pme.minter());
    let published = data_dir.join(id);
    tokio::task::spawn_blocking({
        let staging = staging.clone();
        let data_dir = data_dir.clone();
        move || {
            ingest_staging_dir(
                &staging,
                &data_dir,
                &ParquetCaps::default(),
                &node_catalogs(),
                &encryptor,
            )
        }
    })
    .await
    .unwrap()
    .expect("real-Vault PME ingest");

    for m in parquet_magics(&published) {
        assert_eq!(&m, b"PARE", "real-Vault PME store must be PARE");
    }

    let decryptor = DatasetDecryptor::with_retriever(pme.retriever());
    let rows = tokio::task::spawn_blocking(move || {
        scan_dataset(
            &published,
            "3",
            10_000_000,
            &covid_query(),
            &ParquetCaps::default(),
            &decryptor,
            u64::MAX,
            &mut UnboundedRetention,
        )
    })
    .await
    .unwrap()
    .expect("real-Vault PME scan");
    assert_covid_frequencies(&rows);
}
