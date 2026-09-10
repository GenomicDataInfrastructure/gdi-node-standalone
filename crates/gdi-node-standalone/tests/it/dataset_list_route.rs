//! `GET /datasets` on the management plane, behind an opt-in flag.
//!
//! Two things are asserted, and only one of them is the feature. The route serves the
//! inventory when the operator asked for it. With the flag off it is absent rather than
//! forbidden, because a `403` would confirm the flag exists on a node that declined to
//! answer, while a `404` is also what a node without the route returns.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::build_management_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::{DatasetProvenance, StatusEntry, StatusIndex};
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::state::DatasetState;
use tower::ServiceExt as _;

const VISIBLE_ID: &str = "GDI-EE-UTARTU-20260409143052837";
const HIDDEN_ID: &str = "GDI-EE-UTARTU-20260409143052838";

/// An `AppState` whose status index is persisted to `data_dir`, because the route reads the
/// on-disk index (as the CLI does), not the in-memory cache.
fn state_with_index(data_dir: &std::path::Path, expose: bool) -> AppState {
    // The `primary` bucket is declared, matching the status entries below that claim it
    // as their channel: a bucket channel absent from `[[s3.buckets]]` is an orphan under
    // the offboarding-withhold rule, and its datasets would (correctly) compose to
    // `hidden` — these tests are about the listing itself, not that rule.
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
expose_dataset_list = {expose}

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"

[[s3.buckets]]
name = "primary"
endpoint = "https://s3.test.example.org"
bucket = "gdi-datasets"
"#,
        data_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();

    let mut index = StatusIndex::new();
    for (id, state, channel) in [
        (VISIBLE_ID, DatasetState::Visible, "primary"),
        (HIDDEN_ID, DatasetState::Hidden, "inbox"),
    ] {
        index.insert(
            id.to_owned(),
            StatusEntry {
                state,
                error_message: None,
                channel: channel.to_owned(),
                last_seen_signature: None,
                provenance: DatasetProvenance::Unknown,
            },
        );
    }
    index.store(&data_dir.join(".status.json")).unwrap();

    AppState::new(config, index, NodeIdentities::empty())
}

async fn get(state: AppState, uri: &str) -> (StatusCode, String) {
    let resp = build_management_router(state, None)
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// With the flag on, the route serves the whole inventory — hidden datasets included.
///
/// The hidden one is the assertion that matters: enumerating what a node holds, not just
/// what it serves, is the capability the flag gates and the reason it defaults off.
#[tokio::test]
async fn the_route_lists_every_dataset_when_the_flag_is_on() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let (status, body) = get(state_with_index(&data_dir, true), "/datasets").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let rows = json.as_array().expect("the body is a JSON array");
    assert_eq!(rows.len(), 2, "{body}");
    assert_eq!(rows[0]["id"], VISIBLE_ID);
    assert_eq!(rows[0]["state"], "visible");
    assert_eq!(rows[0]["channel"], "primary");
    assert_eq!(rows[1]["id"], HIDDEN_ID);
    assert_eq!(
        rows[1]["state"], "hidden",
        "the listing must include datasets the node is NOT serving: {body}"
    );
    // Unsuppressed rows omit the field rather than emitting `null` — the same convention
    // the single-id oracle uses, and part of the shape the CLI already prints.
    assert!(rows[0].get("suppressed").is_none(), "{body}");
}

/// With the flag off every inventory route is absent: a 404, not a 403.
///
/// A 403 would answer the question the flag exists to withhold: does this node have an
/// inventory endpoint that someone chose not to expose. A 404 is also what a node without the
/// route returns, so a caller cannot tell the two apart, which is what lets a client treat the
/// route as best-effort.
///
/// The list is derived from `app.rs` rather than written here: an `if` that grows a second
/// route is where a restated list stops covering the new one, and the new route may withhold
/// strictly more than the one already named.
#[tokio::test]
async fn the_routes_are_absent_when_the_flag_is_off() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    // Derived from `app.rs`: the routes behind `[service].expose_dataset_list`, whatever they
    // are today. A restated list here would silently miss a route added behind the flag.
    let gated = crate::route_inventory::paths_gated_on("expose_dataset_list");
    assert!(
        gated.len() >= 2,
        "expected at least two routes behind expose_dataset_list, found {gated:?}"
    );
    for uri in &gated {
        let uri = crate::route_inventory::concretize(uri);
        let (status, _) = get(state_with_index(&data_dir, false), &uri).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "with the flag off {uri} must not exist at all"
        );
    }
}

/// The flag does not gate `GET /datasets/{id}/state`, in either position.
///
/// They share a path prefix, so mounting one conditionally is the kind of change that takes
/// the other with it, and the single-id oracle is what a client polls for dataset state.
#[tokio::test]
async fn the_flag_does_not_gate_the_single_dataset_oracle() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    for expose in [false, true] {
        let (status, body) = get(
            state_with_index(&data_dir, expose),
            &format!("/datasets/{VISIBLE_ID}/state"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the single-id oracle must answer with expose_dataset_list = {expose}: {body}"
        );
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["state"], "visible");
    }
}

/// The route's body is value-identical to what `dataset list --format json` prints — the
/// same rows from the same collector, compared as parsed JSON (key order is not part of the
/// claim), over a non-empty inventory, so the comparison cannot pass vacuously.
///
/// Both go through `list_datasets::collect`, and this is what holds them there: a second
/// pipeline (or a hand-rolled row type beside the shared one) would drift silently, and the
/// symptom would be an operator and a polling client disagreeing about what the node serves.
#[tokio::test]
async fn the_route_and_the_cli_agree_on_the_shape() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = state_with_index(&data_dir, true);
    let config = std::sync::Arc::clone(&state.config);
    let reloadable = state.reloadable();
    let (_, body) = get(state, "/datasets").await;

    let via_cli = gdi_node_standalone::list_datasets::collect(
        &config,
        &gdi_node_standalone::list_datasets::DatasetsFilter::default(),
        &reloadable,
    )
    .unwrap();

    assert!(
        !via_cli.is_empty(),
        "the fixture seeds two datasets; an empty inventory would make this comparison vacuous"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap(),
        serde_json::to_value(&via_cli).unwrap(),
        "the route and the CLI must render the same rows from the same collector"
    );
}

/// A query parameter on an inventory route is refused, not ignored.
///
/// Axum drops unrecognized parameters silently, and on these two routes that default is the
/// wrong one: `?suppressed=true` is the obvious guess for the withheld set, and answering it
/// `200 []` reports — with a success status — that nothing is withheld. The whole point of
/// the `400` is that a mis-spelled question must not read as an authoritative answer.
#[tokio::test]
async fn an_inventory_route_refuses_a_query_parameter_instead_of_ignoring_it() {
    let tmp = tempfile::tempdir().unwrap();
    let state = state_with_index(tmp.path(), true);

    let (status, body) = get(state.clone(), "/datasets?suppressed=true").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a query parameter must be refused, not dropped: {body}"
    );
    assert!(
        body.contains("/datasets/suppressed"),
        "the refusal must name the route that DOES answer the question: {body}"
    );

    let (status, _) = get(state.clone(), "/datasets/suppressed?state=hidden").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the suppressed route takes no parameters either"
    );

    // The bare routes are unaffected — the guard must reject a query, not every request.
    let (status, _) = get(state.clone(), "/datasets").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = get(state, "/datasets/suppressed").await;
    assert_eq!(status, StatusCode::OK);
}

/// `GET /datasets/suppressed` answers the question the plain listing structurally cannot.
///
/// A take-down (`Remove`) erases the local copy and purges the status entry, so the dataset
/// survives only as an override. `collect` synthesizes a row for such an id only when the
/// suppressed filter is set, so a completed erasure cannot leak into the plain listing as
/// merely "hidden". Both halves are asserted: absent from `/datasets`, present on
/// `/datasets/suppressed`. Asserting only the second would pass on a build that leaked it into
/// both.
#[tokio::test]
async fn the_suppressed_route_reports_a_withheld_id_the_plain_listing_cannot() {
    use gdi_node_standalone_core::suppression::{SuppressMode, Suppression, suppressions_subdir};

    let tmp = tempfile::tempdir().unwrap();
    let state = state_with_index(tmp.path(), true);

    // An override for an id with no status entry: the shape a take-down leaves behind.
    let erased = "GDI-EE-UTARTU-20260409143052999";
    gdi_node_standalone_core::suppression::write_file(
        &suppressions_subdir(&state.config.service.override_dir_resolved()),
        erased,
        &Suppression {
            mode: SuppressMode::Remove,
            reason: "erasure request".to_owned(),
            at: String::new(),
        },
    )
    .unwrap();

    let (status, plain) = get(state.clone(), "/datasets").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !plain.contains(erased),
        "an erased id must NOT appear in the plain listing (it would read as merely hidden): {plain}"
    );

    let (status, withheld) = get(state, "/datasets/suppressed").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        withheld.contains(erased),
        "the suppressed route must report the withheld id: {withheld}"
    );
    assert!(
        !withheld.contains("erasure request"),
        "the justification stays off this plane, as on every other route: {withheld}"
    );
}

/// An orphaned channel's dataset — its `[[s3.buckets]]` entry removed while the status
/// index still owns it — must read `hidden` on the listing and the oracle, with the
/// masked declared state in `source_state`.
///
/// The serve path withholds orphans inside the hydrate projection, and that withhold is in
/// neither store the lock-free surfaces read. They have to compose the same predicate
/// (`channel_is_orphaned`), or `dataset list` reports `visible` for a dataset the node is
/// withholding — the surface disagreement this suite pins for suppressions, in the
/// offboarding direction.
#[tokio::test]
async fn an_orphaned_channels_dataset_reads_hidden_on_listing_and_oracle() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    // The fixture writes entries for channels `primary` (declared) and a `departed`
    // channel no config declares — the post-offboarding shape.
    let orphan_id = "GDI-EE-UTARTU-20260409143052899";
    let state = {
        let state = state_with_index(&data_dir, true);
        let mut status = state.status.lock().unwrap();
        status.insert(
            orphan_id.to_owned(),
            StatusEntry {
                state: DatasetState::Visible,
                error_message: None,
                channel: "departed".to_owned(),
                last_seen_signature: None,
                provenance: DatasetProvenance::Unknown,
            },
        );
        let path = data_dir.join(".status.json");
        status.store(&path).unwrap();
        drop(status);
        state
    };

    let (status_code, listing) = get(state.clone(), "/datasets").await;
    assert_eq!(status_code, StatusCode::OK);
    let rows: Vec<serde_json::Value> = serde_json::from_str(&listing).unwrap();
    let row = rows
        .iter()
        .find(|r| r["id"] == orphan_id)
        .expect("the orphan is still inventoried");
    assert_eq!(
        row["state"], "hidden",
        "an orphaned channel's dataset must not be listed as visible: {row}"
    );
    assert_eq!(
        row["source_state"], "visible",
        "the mask is explained: {row}"
    );
    // The declared channel's dataset is untouched by the orphan rule.
    let kept = rows.iter().find(|r| r["id"] == VISIBLE_ID).unwrap();
    assert_eq!(kept["state"], "visible", "{kept}");

    // The withheld inventory must name it too: `doctor` counts an orphan as withheld and
    // the plain listing shows it `hidden`, so a `/datasets/suppressed` that omits it reads
    // as authoritative and is not.
    let (status_code, withheld) = get(state.clone(), "/datasets/suppressed").await;
    assert_eq!(status_code, StatusCode::OK);
    let withheld: Vec<serde_json::Value> = serde_json::from_str(&withheld).unwrap();
    let row = withheld
        .iter()
        .find(|r| r["id"] == orphan_id)
        .unwrap_or_else(|| {
            panic!("an orphan-withheld dataset must appear on /datasets/suppressed: {withheld:?}")
        });
    assert_eq!(row["state"], "hidden", "{row}");
    assert_eq!(row["source_state"], "visible", "{row}");

    let (status_code, oracle) = get(state, &format!("/datasets/{orphan_id}/state")).await;
    assert_eq!(status_code, StatusCode::OK);
    let oracle: serde_json::Value = serde_json::from_str(&oracle).unwrap();
    assert_eq!(
        oracle["state"], "hidden",
        "the oracle's index-only arm composes orphan-ness too: {oracle}"
    );
    assert_eq!(oracle["source_state"], "visible", "{oracle}");
}

/// The listing and the single-id state oracle give the same answer for a withheld id.
///
/// They read different stores: the oracle reads the running node's cache and the listing
/// reads the on-disk status index, and an operator withhold reaches only the first. The node
/// never writes it back to the index, and should not; the override is the durable record, and
/// baking `hidden` into the index would survive the override's removal. So the listing
/// composes the override store over the index. Hiding a `visible` dataset makes both surfaces
/// say `hidden` at the same instant.
///
/// Without the composition the listing answers `visible` for a dataset the node is actively
/// withholding, which is the one question an operator runs it to settle. Asserting the two
/// together is what matters: either alone passes on a build where they disagree.
#[tokio::test]
async fn the_listing_and_the_oracle_agree_that_a_withheld_dataset_is_hidden() {
    use gdi_node_standalone_core::suppression::{SuppressMode, Suppression, suppressions_subdir};

    let tmp = tempfile::tempdir().unwrap();
    let state = state_with_index(tmp.path(), true);

    // The oracle reads the cache and falls back to the index only for an id it has not
    // hydrated, so the dataset has to be cached for this to exercise the real path — a
    // running node hydrates it at startup.
    let manifest = crate::fixtures::manifest_for(VISIBLE_ID, "gdi-aggregated", 1);
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        gdi_node_standalone_core::cache::DatasetEntry {
            id: VISIBLE_ID.to_owned(),
            metadata: manifest.metadata,
            config: manifest.config,
            state: DatasetState::Visible,
            metadata_modified: None,
        },
    );

    gdi_node_standalone_core::suppression::write_file(
        &suppressions_subdir(&state.config.service.override_dir_resolved()),
        VISIBLE_ID,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "audit probe".to_owned(),
            at: String::new(),
        },
    )
    .unwrap();
    // What the running node does on SIGUSR1 — the state the oracle then reports.
    state.reload_suppressions();
    state.apply_suppressions_to_cache();

    let (status, oracle) = get(state.clone(), &format!("/datasets/{VISIBLE_ID}/state")).await;
    assert_eq!(status, StatusCode::OK);
    let oracle: serde_json::Value = serde_json::from_str(&oracle).unwrap();
    assert_eq!(
        oracle["state"], "hidden",
        "the oracle withholds it: {oracle}"
    );

    let (status, listing) = get(state, "/datasets").await;
    assert_eq!(status, StatusCode::OK);
    let rows: Vec<serde_json::Value> = serde_json::from_str(&listing).unwrap();
    let row = rows
        .iter()
        .find(|r| r["id"] == VISIBLE_ID)
        .expect("the withheld id is still INVENTORIED, just not served as visible");

    assert_eq!(
        row["state"], oracle["state"],
        "listing and oracle must not answer the same question differently: {row}"
    );
    assert_eq!(row["suppressed"], "hide", "the mode explains WHY: {row}");
    assert_eq!(
        row["source_state"], "visible",
        "and the masked index value survives for triage: {row}"
    );
    assert!(
        !listing.contains("audit probe"),
        "the justification stays off this plane: {listing}"
    );
}

/// A bucket added by a config reload is declared: its datasets must stop reading as
/// orphan-withheld the moment the reload lands.
///
/// The reload swaps the reloadable snapshot and starts the bucket's monitor, but never
/// touches the boot `state.config`, so orphan-ness must be derived from the reloaded
/// snapshot. Derived from the boot config, the oracle would answer `hidden` for datasets the
/// public plane is serving. Gated on `s3` because the reload re-runs the boot preflight,
/// which rejects `[[s3.buckets]]` on a build without the feature.
#[cfg(feature = "s3")]
#[tokio::test]
async fn a_reload_that_re_declares_a_bucket_stops_the_oracle_calling_it_orphaned() {
    use gdi_node_standalone::state::ReloadTrigger;

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let config_path = tmp.path().join("node.toml");
    let toml = |departed_declared: bool| {
        format!(
            r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
expose_dataset_list = true

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"

[[s3.buckets]]
name = "primary"
endpoint = "https://s3.test.example.org"
bucket = "gdi-datasets"
{}
"#,
            data_dir.display(),
            if departed_declared {
                "[[s3.buckets]]\nname = \"departed\"\nendpoint = \"https://s3.test.example.org\"\nbucket = \"gdi-departed\"\n"
            } else {
                ""
            }
        )
    };
    std::fs::write(&config_path, toml(false)).unwrap();
    let config = ServiceConfig::load(Some(&config_path)).unwrap();
    config.preflight().unwrap();

    let orphan_id = "GDI-EE-UTARTU-20260409143052898";
    let mut index = StatusIndex::new();
    index.insert(
        orphan_id.to_owned(),
        StatusEntry {
            state: DatasetState::Visible,
            error_message: None,
            channel: "departed".to_owned(),
            last_seen_signature: None,
            provenance: DatasetProvenance::Unknown,
        },
    );
    index.store(&data_dir.join(".status.json")).unwrap();
    let state = AppState::new(config, index, NodeIdentities::empty());

    let (_, before) = get(state.clone(), &format!("/datasets/{orphan_id}/state")).await;
    let before: serde_json::Value = serde_json::from_str(&before).unwrap();
    assert_eq!(
        before["state"], "hidden",
        "precondition: orphaned at boot: {before}"
    );

    // The operator re-declares the bucket and reloads.
    std::fs::write(&config_path, toml(true)).unwrap();
    state
        .reload_config_from(&config_path, ReloadTrigger::Http)
        .expect("the reloaded file passes the boot preflight");

    let (_, after) = get(state.clone(), &format!("/datasets/{orphan_id}/state")).await;
    let after: serde_json::Value = serde_json::from_str(&after).unwrap();
    assert_eq!(
        after["state"], "visible",
        "a bucket the reload re-declared is not orphaned; the oracle must read the LIVE \
         channel set, not the boot config: {after}"
    );
    assert!(
        after.get("source_state").is_none(),
        "nothing is masked: {after}"
    );
    let (_, listing) = get(state, "/datasets").await;
    let rows: Vec<serde_json::Value> = serde_json::from_str(&listing).unwrap();
    let row = rows.iter().find(|r| r["id"] == orphan_id).unwrap();
    assert_eq!(row["state"], "visible", "the listing agrees: {row}");
}

/// Two overrides on one dataset — `dataset hide <id>` plus `channel take-down <name>` — are
/// independently reachable, and the node enforces the most restrictive (`Remove` erases).
/// The oracle must report that same mode, not the id-level record it happens to find first:
/// `GET /datasets` already says `remove`, and an oracle answering `hide` for an id the node
/// is erasing understates an irreversible action while the two routes disagree at the same
/// instant.
#[tokio::test]
async fn the_oracle_reports_the_most_restrictive_of_id_and_channel_overrides() {
    use gdi_node_standalone_core::suppression::{SuppressMode, Suppression, suppressions_subdir};

    let tmp = tempfile::tempdir().unwrap();
    let state = state_with_index(tmp.path(), true);
    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    gdi_node_standalone_core::suppression::write_file(
        &sub,
        VISIBLE_ID,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "embargo".to_owned(),
            at: String::new(),
        },
    )
    .unwrap();
    gdi_node_standalone_core::suppression::write_channel_file(
        &sub,
        "primary",
        &Suppression {
            mode: SuppressMode::Remove,
            reason: "provider compromised".to_owned(),
            at: String::new(),
        },
    )
    .unwrap();
    // The reload half only (no erase): the question is what each surface reports.
    state.reload_suppressions();
    state.apply_suppressions_to_cache();

    let (status, listing) = get(state.clone(), "/datasets").await;
    assert_eq!(status, StatusCode::OK);
    let rows: Vec<serde_json::Value> = serde_json::from_str(&listing).unwrap();
    let row = rows.iter().find(|r| r["id"] == VISIBLE_ID).unwrap();
    assert_eq!(
        row["suppressed"], "remove",
        "the listing composes the most restrictive: {row}"
    );

    let (status, oracle) = get(state, &format!("/datasets/{VISIBLE_ID}/state")).await;
    assert_eq!(status, StatusCode::OK);
    let oracle: serde_json::Value = serde_json::from_str(&oracle).unwrap();
    assert_eq!(
        oracle["suppression"]["mode"], "remove",
        "the oracle must report the mode the node ENFORCES — the most restrictive of the \
         id-level and channel-level overrides — exactly as the listing does: {oracle}"
    );
}
