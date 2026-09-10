//! End-to-end coverage for the operator enforcement and recovery flows.
//!
//! Four groups, all driven through the real ingest runtime and `AppState` rather than
//! through unit seams: the writer-key allow-list, where `[ingest].writer_policy = "enforce"`
//! quarantines an unlisted or unidentified writer; the override store, covering suppression
//! and node-local metadata overlays, how they are applied on every path (signal, periodic
//! reload, reconcile) and how they fail closed when the store is lost or corrupted; the
//! reingest paths, both `dataset reingest` restoring a quarantined inbox artifact and the
//! bucket-channel marker a node clears a recorded signature for; and channel-level
//! suppression of the `inbox` channel.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
#![expect(
    clippy::similar_names,
    reason = "node/writer sk/pk are the standard, clearest crypto naming"
)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::ingest_runtime::IngestRuntime;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::{DatasetEntry, DatasetProvenance, StatusEntry, StatusIndex};
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::crypt4gh::{
    PublicKey, SecretKey, encrypt, generate_keypair, public_key_fingerprint,
};
use gdi_node_standalone_core::model::{LocalizedText, MetadataOverlay};
use gdi_node_standalone_core::reingest_request;
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::suppression::{
    SuppressMode, Suppression, remove_channel_file, remove_file, suppressions_subdir,
    write_channel_file, write_file,
};

use crate::fixtures::{
    await_ingest_quiescent, build_covid_staging_goe, manifest_for, poll_until, write_identity,
};

const CATALOG: &str = "gdi-aggregated";
const ID: &str = "GDI-EE-UTARTU-20260409143052837";

/// Build `{id}.tar.c4gh` encrypted to `recipient`, signed by `sender_sk`, under `dest`.
fn build_tar_c4gh(
    work: &Path,
    dest: &Path,
    id: &str,
    recipient: &PublicKey,
    sender_sk: &SecretKey,
) -> PathBuf {
    let staging = build_covid_staging_goe(work, id);
    let tar_path = work.join(format!("{id}.tar"));
    {
        let file = std::fs::File::create(&tar_path).unwrap();
        let mut builder = tar::Builder::new(file);
        builder
            .append_path_with_name(staging.join("manifest.json"), "manifest.json")
            .unwrap();
        for entry in std::fs::read_dir(&staging).unwrap() {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            if name.starts_with("allele-freq.") && name.ends_with(".parquet") {
                builder.append_path_with_name(&p, &name).unwrap();
            }
        }
        builder.into_inner().unwrap().sync_all().unwrap();
    }
    std::fs::remove_dir_all(&staging).unwrap();
    let pkg = dest.join(format!("{id}.tar.c4gh"));
    let mut reader = std::fs::File::open(&tar_path).unwrap();
    let mut writer = std::fs::File::create(&pkg).unwrap();
    encrypt(
        &mut reader,
        &mut writer,
        std::slice::from_ref(recipient),
        sender_sk,
    )
    .unwrap();
    writer.sync_all().unwrap();
    pkg
}

fn enforce_config(
    data_dir: &Path,
    inbox: &Path,
    identity: &Path,
    allowed_fp: &str,
) -> ServiceConfig {
    policy_config(data_dir, inbox, identity, allowed_fp, "enforce")
}

fn policy_config(
    data_dir: &Path,
    inbox: &Path,
    identity: &Path,
    allowed_fp: &str,
    policy: &str,
) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"

[keys]
identities = ["{}"]

[ingest]
writer_policy = "{policy}"
inbox_allowed_writer_fingerprints = ["{allowed_fp}"]
"#,
        data_dir.display(),
        inbox.display(),
        identity.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

/// Drive an `enforce`-policy ingest of a package signed by a known writer key. When the
/// writer is allow-listed the dataset publishes; otherwise it is quarantined.
async fn run_enforce(writer_is_allowlisted: bool) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let keys = tmp.path().join("keys");
    let work = tmp.path().join("work");
    for d in [&data_dir, &inbox, &keys, &work] {
        std::fs::create_dir_all(d).unwrap();
    }

    let (node_sk, node_pk) = generate_keypair();
    let identity_file = keys.join("node.c4gh");
    write_identity(&identity_file, &node_sk);

    // A known writer keypair gives a known fingerprint to allow-list, or not.
    let (writer_sk, writer_pk) = generate_keypair();
    let writer_fp = public_key_fingerprint(&writer_pk);

    build_tar_c4gh(&work, &inbox, ID, &node_pk, &writer_sk);
    std::fs::write(
        inbox.join(format!("{ID}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    // Allow-list either this writer or a different key. The list is non-empty either way,
    // so `enforce` boots.
    let allowed = if writer_is_allowlisted {
        writer_fp
    } else {
        public_key_fingerprint(&generate_keypair().1)
    };
    let config = enforce_config(&data_dir, &inbox, &identity_file, &allowed);
    let identities = NodeIdentities::load(&config).unwrap();
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());
    runtime.scan_once().await;

    if writer_is_allowlisted {
        poll_until(Duration::from_secs(15), || {
            state
                .cache
                .get(ID)
                .is_some_and(|e| e.state == DatasetState::Visible)
        })
        .await;
        await_ingest_quiescent(&runtime).await;
        assert!(
            !inbox.join(format!("{ID}.tar.c4gh")).exists(),
            "an allow-listed package publishes and is consumed"
        );
    } else {
        poll_until(Duration::from_secs(15), || {
            let status = state.status.lock().unwrap();
            status
                .get(ID)
                .is_some_and(|e| e.state == DatasetState::Error)
        })
        .await;
        await_ingest_quiescent(&runtime).await;
        {
            let status = state.status.lock().unwrap();
            assert_eq!(
                status.get(ID).unwrap().error_message,
                Some(gdi_node_standalone_core::error::ErrorClass::WriterRejected),
                "a non-allow-listed writer is a permanent writer-rejected error"
            );
        }
        assert!(
            inbox.join(".rejected").join(ID).exists(),
            "the rejected package is quarantined, not published"
        );
        assert!(
            !state
                .cache
                .get(ID)
                .is_some_and(|e| e.state == DatasetState::Visible),
            "a rejected writer's dataset must never be served"
        );
        // The payload the pipeline stored before the writer gate ran must be removed from
        // data_dir, not just left uncached. Otherwise the periodic `hydrate_from_disk`
        // re-admits it as `Hidden` and the `visible` sidecar dropped above promotes it to
        // served, which bypasses `enforce`.
        assert!(
            !data_dir.join(ID).exists(),
            "a writer-rejected package's stored payload must be removed from data_dir so it \
             cannot be re-admitted and promoted to served by its sidecar"
        );
    }
}

#[tokio::test]
async fn enforce_quarantines_a_non_allowlisted_writer() {
    run_enforce(false).await;
}

#[tokio::test]
async fn enforce_publishes_an_allowlisted_writer() {
    run_enforce(true).await;
}

// ---------------------------------------------------------------------------
// AppState suppression wiring: reload_suppressions + apply_suppressions_to_cache
// ---------------------------------------------------------------------------

/// Build an `AppState` with `[service].override_dir` configured and one dataset already
/// `Visible` in both the cache and the status index, on channel `"inbox"`. The suppression
/// wiring operates on the cache and status pair alone, so a directly-constructed entry is
/// enough and skips the ingest and VCF conversion.
fn state_with_visible_dataset(id: &str) -> (AppState, tempfile::TempDir) {
    state_with_visible_dataset_opts(id, false)
}

/// As [`state_with_visible_dataset`], with `[service].require_override_store` settable
/// so the store-presence posture can be exercised.
fn state_with_visible_dataset_opts(
    id: &str,
    require_override_store: bool,
) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let override_dir = tmp.path().join("overrides");
    std::fs::create_dir_all(&data_dir).unwrap();

    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
override_dir = "{}"
require_override_store = {require_override_store}
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        override_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();

    let mut index = StatusIndex::new();
    index.insert(
        id.to_owned(),
        StatusEntry {
            state: DatasetState::Visible,
            error_message: None,
            channel: "inbox".to_owned(),
            last_seen_signature: None,
            provenance: DatasetProvenance::Unknown,
        },
    );

    let state = AppState::new(config, index, NodeIdentities::empty());

    let manifest = manifest_for(id, CATALOG, 1);
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        DatasetEntry {
            id: id.to_owned(),
            metadata: manifest.metadata,
            config: manifest.config,
            state: DatasetState::Visible,
            metadata_modified: None,
        },
    );

    (state, tmp)
}

#[tokio::test]
async fn reload_keeps_suppressions_when_a_required_store_vanishes() {
    // The store is destroyed while the node is up: a volume swap, an over-broad cleanup.
    // `suppression::load` reports an unreadable root as the empty set, so an unguarded reload
    // would adopt it and un-hide every withheld dataset at the next reconcile. With the store
    // declared required, the last known-good set survives instead.
    let (state, _tmp) = state_with_visible_dataset_opts(ID, true);

    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    write_file(
        &sub,
        ID,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "consent withdrawn".into(),
            at: String::new(),
        },
    )
    .unwrap();
    state.reload_suppressions();
    assert!(
        state
            .suppressions
            .read()
            .unwrap()
            .effective(ID, "inbox")
            .is_some(),
        "sanity: the suppression loaded"
    );

    // The whole store root disappears.
    std::fs::remove_dir_all(state.config.service.override_dir_resolved()).unwrap();
    state.reload_suppressions();

    // Assert on the set, not the cache: `apply_suppressions_to_cache` only withholds and
    // never un-hides, so a cache assertion would pass whether or not the guard exists. The
    // set is what the reconcile and re-ingest paths consult.
    assert!(
        state
            .suppressions
            .read()
            .unwrap()
            .effective(ID, "inbox")
            .is_some(),
        "a required store that vanished must NOT be read as 'no suppressions' — the \
         last known-good set must survive"
    );
}

#[tokio::test]
async fn reload_keeps_local_overlays_when_a_required_store_vanishes() {
    // Same destroyed-store reasoning as the suppression guard: an emptied overlay set
    // reverts every operator metadata correction to its source-resolved value.
    let (state, _tmp) = state_with_visible_dataset_opts(ID, true);

    let dir = gdi_node_standalone_core::overlay_override::overlays_subdir(
        &state.config.service.override_dir_resolved(),
    );
    let patch = title_patch("corrected title");
    gdi_node_standalone_core::overlay_override::write_file(&dir, ID, &patch).unwrap();
    state.reload_local_overlays();
    assert!(
        state.local_overlays.read().unwrap().contains(ID),
        "sanity: the overlay loaded"
    );

    std::fs::remove_dir_all(state.config.service.override_dir_resolved()).unwrap();
    state.reload_local_overlays();

    assert!(
        state.local_overlays.read().unwrap().contains(ID),
        "a required store that vanished must NOT silently revert operator corrections"
    );
}

/// Overlay twin of `an_absent_store_does_not_lift_withholds_a_node_is_currently_holding`,
/// with `require_override_store = false`.
///
/// The overlay store has the same absent-versus-unreadable asymmetry as the suppression
/// store. Adopting the empty set drops every id's operator-over-source precedence claim, and
/// `reconcile_overlay_reverts` then re-publishes the source metadata each override was
/// redacting. A correction is often a redaction, so that is a disclosure.
#[tokio::test]
async fn an_absent_store_does_not_revert_corrections_a_node_is_currently_serving() {
    let (state, _tmp) = state_with_visible_dataset_opts(ID, false);

    let dir = gdi_node_standalone_core::overlay_override::overlays_subdir(
        &state.config.service.override_dir_resolved(),
    );
    let patch = title_patch("corrected title");
    gdi_node_standalone_core::overlay_override::write_file(&dir, ID, &patch).unwrap();
    state.reload_local_overlays();
    assert!(
        state.local_overlays.read().unwrap().contains(ID),
        "sanity: the overlay loaded"
    );

    std::fs::remove_dir_all(state.config.service.override_dir_resolved()).unwrap();
    state.reload_local_overlays();

    assert!(
        state.local_overlays.read().unwrap().contains(ID),
        "the store vanished under a node that was SERVING this correction; the last-good \
         overlay set must be kept rather than reverting to source metadata, regardless of \
         require_override_store"
    );
}

/// An absent store must not lift a withhold this node is currently applying, even with
/// `require_override_store = false`, the shipped default.
///
/// Two cases look alike and are not:
///
/// * a node that has never held an override, where "absent" means "no overrides". That case
///   is covered by `an_absent_store_still_reads_as_empty_on_a_node_holding_nothing` below.
/// * a node that is withholding, where "absent" means the store was destroyed under it.
///   Adopting the empty set there re-discloses every hidden dataset and every `Remove`
///   take-down written to satisfy an erasure request.
///
/// The second is reachable by ordinary infrastructure events on the default configuration: a
/// detached volume, an unmounted network export, a mount-path typo. `POST /reconcile`,
/// when `[control].enabled`, is an unauthenticated remote trigger for the reload that does
/// it. Keying the guard on `require_override_store` alone would leave it opt-in; keying it
/// also on "am I holding something right now" closes it with no new state and no false
/// refusals.
#[tokio::test]
async fn an_absent_store_does_not_lift_withholds_a_node_is_currently_holding() {
    let (state, _tmp) = state_with_visible_dataset_opts(ID, false);

    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    write_file(
        &sub,
        ID,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "t".into(),
            at: String::new(),
        },
    )
    .unwrap();
    state.reload_suppressions();
    state.apply_suppressions_to_cache();
    assert_eq!(state.cache.get(ID).unwrap().state, DatasetState::Hidden);

    std::fs::remove_dir_all(state.config.service.override_dir_resolved()).unwrap();
    state.reload_suppressions();

    assert!(
        state
            .suppressions
            .read()
            .unwrap()
            .effective(ID, "inbox")
            .is_some(),
        "the store vanished under a node that was WITHHOLDING this id; the last-good set \
         must be kept rather than lifting the withhold, regardless of require_override_store"
    );
}

/// The complement: a node holding nothing still treats an absent store as the empty set, and
/// is not wedged by the guard.
///
/// This is what stops the guard above from becoming a false refusal on a fresh node. It is a
/// no-op by construction, because with the in-memory set already empty, "keep last-good" and
/// "adopt empty" are the same outcome. The second half proves the reload path still works
/// afterwards: a restored store is picked up normally.
#[tokio::test]
async fn an_absent_store_still_reads_as_empty_on_a_node_holding_nothing() {
    let (state, _tmp) = state_with_visible_dataset_opts(ID, false);

    // Never held an override, and the store root is absent. `remove_dir_all` is tolerated
    // rather than unwrapped: this harness does not materialise `override_dir`, only the real
    // boot path does, so the root has never existed here. That is the condition under test,
    // so assert it rather than assume it.
    let root = state.config.service.override_dir_resolved();
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        !root.exists(),
        "precondition: the override store root is absent"
    );

    state.reload_suppressions();
    assert!(
        state
            .suppressions
            .read()
            .unwrap()
            .effective(ID, "inbox")
            .is_none(),
        "a node that never held an override must still read an absent store as empty"
    );

    // ...and the path is not wedged: restore the store and it is honoured again.
    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    write_file(
        &sub,
        ID,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "t".into(),
            at: String::new(),
        },
    )
    .unwrap();
    state.reload_suppressions();
    assert!(
        state
            .suppressions
            .read()
            .unwrap()
            .effective(ID, "inbox")
            .is_some(),
        "a restored store must be adopted normally after an absent-store reload"
    );
}

#[tokio::test]
async fn suppression_remove_also_forces_hidden_but_does_not_erase() {
    // `apply_suppressions_to_cache` is the withhold half only: it resolves `Remove` to the
    // same forced-Hidden as `Hide`, leaving `data_dir/{id}/` and the status entry intact. The
    // evict-and-erase completion of `Remove` lives in `enforce_suppressions`, exercised by
    // `enforce_suppressions_erases_a_remove_dataset` below. Keeping the two separate lets the
    // periodic reload re-apply the instant withhold without repeating the async erase.
    let (state, _tmp) = state_with_visible_dataset(ID);

    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    write_file(
        &sub,
        ID,
        &Suppression {
            mode: SuppressMode::Remove,
            reason: "consent withdrawn".into(),
            at: String::new(),
        },
    )
    .unwrap();
    state.reload_suppressions();
    state.apply_suppressions_to_cache();

    assert_eq!(
        state.cache.get(ID).unwrap().state,
        DatasetState::Hidden,
        "Remove must withhold (never leave Visible) even though full erasure is deferred"
    );
    assert!(
        state.status.lock().unwrap().get(ID).is_some(),
        "the status entry must NOT be purged by this method (that would risk a \
         re-disclosure ghost with data_dir/{{id}}/ still on disk)"
    );
    assert!(
        state.cache.get(ID).is_some(),
        "the cache entry must NOT be evicted by this method"
    );
}

#[tokio::test]
async fn apply_suppressions_to_cache_is_a_noop_without_a_suppression() {
    let (state, _tmp) = state_with_visible_dataset(ID);

    state.reload_suppressions(); // no suppression file exists: an empty set
    state.apply_suppressions_to_cache();

    assert_eq!(
        state.cache.get(ID).unwrap().state,
        DatasetState::Visible,
        "no suppression exists for this id; apply must not touch its state"
    );
}

#[tokio::test]
async fn lifting_a_suppression_is_not_restored_by_apply_alone() {
    // Full lift-restore needs the reconcile: SIGUSR1 runs reload, apply, then reconcile,
    // which re-resolves and restores the source state. This test pins the apply half of that
    // contract. `apply_suppressions_to_cache` is withhold-only, so lifting a suppression and
    // re-applying must not by itself flip the dataset back to Visible.
    let (state, _tmp) = state_with_visible_dataset(ID);
    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    write_file(
        &sub,
        ID,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "t".into(),
            at: String::new(),
        },
    )
    .unwrap();
    state.reload_suppressions();
    state.apply_suppressions_to_cache();
    assert_eq!(
        state.cache.get(ID).unwrap().state,
        DatasetState::Hidden,
        "a Hide suppression must force the cached entry to Hidden"
    );

    // Lift it.
    remove_file(&sub, ID).unwrap();
    state.reload_suppressions();
    state.apply_suppressions_to_cache();

    assert_eq!(
        state.cache.get(ID).unwrap().state,
        DatasetState::Hidden,
        "lifting a suppression is not undone by apply_suppressions_to_cache alone; \
         restoring the source-resolved state is the reconcile's responsibility"
    );
}

// ---------------------------------------------------------------------------
// SIGUSR1 immediacy, real Remove erasure, and the pre-emptive ingest gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sigusr1_style_apply_hides_immediately() {
    // The SIGUSR1 handler's core pathway is `reload_suppressions()` then
    // `enforce_suppressions()`. Drive that directly, with no real signal, and assert a
    // suppression written after boot is honoured immediately rather than on the next poll.
    let (state, _tmp) = state_with_visible_dataset(ID);
    assert_eq!(state.cache.get(ID).unwrap().state, DatasetState::Visible);

    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    write_file(
        &sub,
        ID,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "embargo".into(),
            at: String::new(),
        },
    )
    .unwrap();

    // The SIGUSR1 pathway.
    state.reload_suppressions();
    state.enforce_suppressions().await;

    assert_eq!(
        state.cache.get(ID).unwrap().state,
        DatasetState::Hidden,
        "the SIGUSR1 reload+enforce pathway must hide a just-written suppression at once"
    );
}

#[tokio::test]
async fn enforce_suppressions_erases_a_remove_dataset() {
    // `enforce_suppressions` completes `Remove` to a real erasure: the id 404s, with status
    // and cache purged, and `data_dir/{id}/` is gone.
    let (state, _tmp) = state_with_visible_dataset(ID);
    // Materialise the on-disk dataset dir the erase must remove.
    let dir = state.config.service.data_dir.join(ID);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        test_util::stored_manifest_json(ID),
    )
    .unwrap();
    assert!(dir.is_dir());

    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    write_file(
        &sub,
        ID,
        &Suppression {
            mode: SuppressMode::Remove,
            reason: "consent withdrawn".into(),
            at: String::new(),
        },
    )
    .unwrap();
    state.reload_suppressions();
    state.enforce_suppressions().await;

    assert!(
        state.cache.get(ID).is_none(),
        "a Remove suppression must EVICT the cache entry (not merely hide it)"
    );
    assert!(
        state.status.lock().unwrap().get(ID).is_none(),
        "a Remove suppression must PURGE the status entry (the state endpoint 404s)"
    );
    assert!(
        !dir.exists(),
        "a Remove suppression must ERASE data_dir/{{id}}/ from disk"
    );
}

#[tokio::test]
async fn preemptive_suppression_blocks_ingest() {
    // A suppression authored for an id before its package is ever presented: the running
    // node must not ingest or serve it. This is both the pre-emptive block and the anti-undo
    // guarantee, since a still-present source package cannot re-materialise a suppressed id.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let override_dir = tmp.path().join("overrides");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }

    // A keyless node: plaintext staging dirs ingest without any key material.
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
override_dir = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        inbox.display(),
        override_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();

    // Suppress the id before presenting its package.
    let sub = suppressions_subdir(&config.service.override_dir_resolved());
    write_file(
        &sub,
        ID,
        &Suppression {
            mode: SuppressMode::Remove,
            reason: "pre-emptive".into(),
            at: String::new(),
        },
    )
    .unwrap();

    // Now drop the package into the inbox.
    crate::fixtures::place_covid_staging_into_inbox(&inbox, ID, CATALOG);
    std::fs::write(
        inbox.join(format!("{ID}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    // `AppState::new` loads the suppression store (the boot behaviour), so the gate is
    // armed before the very first scan.
    let identities = NodeIdentities::load(&config).unwrap();
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());
    runtime.scan_once().await;
    await_ingest_quiescent(&runtime).await;

    assert!(
        state.cache.get(ID).is_none(),
        "a pre-emptively-suppressed id must never enter the served cache"
    );
    assert!(
        state.status.lock().unwrap().get(ID).is_none(),
        "and never acquire a status entry"
    );
    assert!(
        !data_dir.join(ID).exists(),
        "and no dataset dir may be materialised for it"
    );
}

#[tokio::test]
async fn reingest_restores_a_quarantined_dataset_and_the_node_re_ingests_it() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let work = tmp.path().join("work");
    for d in [&data_dir, &inbox, &work] {
        std::fs::create_dir_all(d).unwrap();
    }

    // A keyless node: plaintext staging dirs ingest without any key material.
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        inbox.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();

    // Simulate a prior permanent failure: a (now-valid) staging dir quarantined under
    // inbox/.rejected/{id}, plus the matching `error` status entry.
    let staging = build_covid_staging_goe(&work, ID);
    let rejected = inbox.join(".rejected");
    std::fs::create_dir_all(&rejected).unwrap();
    std::fs::rename(&staging, rejected.join(ID)).unwrap();

    let mut index = StatusIndex::new();
    index.insert(
        ID.to_owned(),
        StatusEntry {
            state: DatasetState::Error,
            error_message: Some(gdi_node_standalone_core::error::ErrorClass::UnknownCatalog),
            channel: "inbox".to_owned(),
            last_seen_signature: None,
            provenance: DatasetProvenance::Unknown,
        },
    );

    // `reingest` moves the artifact back into the inbox (borrow the config first).
    gdi_node_standalone::dataset_cmd::reingest(&config, ID).unwrap();
    assert!(
        inbox.join(ID).is_dir(),
        "reingest restored the staging dir to the inbox"
    );
    assert!(!rejected.join(ID).exists(), "it is no longer quarantined");

    // The running node re-ingests it on the next scan, since an `error` id always
    // re-ingests, and the failed dataset publishes.
    let identities = NodeIdentities::load(&config).unwrap();
    let state = AppState::new(config, index, identities);
    let runtime = IngestRuntime::start(state.clone());
    runtime.scan_once().await;
    poll_until(Duration::from_secs(15), || {
        state
            .cache
            .get(ID)
            .is_some_and(|e| matches!(e.state, DatasetState::Visible | DatasetState::Hidden))
    })
    .await;
}

// ---------------------------------------------------------------------------
// The periodic full-reload safety net must re-read the suppression store, not
// merely re-apply the already-loaded set.
// ---------------------------------------------------------------------------

/// An override written while the node is live is honoured within one poll, even if nobody
/// signals the node.
///
/// The CLI does not signal the node; it prints how to, because the shipped image is
/// `distroless` with no `kill` binary and a one-shot process cannot safely find the serving
/// PID. An operator who acts on that hint applies the override at once, by `SIGUSR1` or by
/// `POST /reconcile`. The periodic [`IngestRuntime::full_reload`] is what honours it when
/// nobody does, and it is the only path that holds when the operator writes the file and
/// walks away.
///
/// This drives that periodic path alone: no SIGUSR1, no `POST /reconcile`, no direct
/// `reload_suppressions` or `enforce_suppressions` call. It asserts a `hide` written after
/// the dataset is already live is picked up, then escalates to a `take-down` (`Remove`) and
/// asserts the periodic path also completes its evict-and-erase.
#[tokio::test]
async fn full_reload_rereads_suppressions_written_against_a_live_node() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let override_dir = tmp.path().join("overrides");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }

    // A keyless node: plaintext staging dirs ingest without any key material.
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
override_dir = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        inbox.display(),
        override_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();

    // No suppression exists at boot: the dataset ingests and publishes normally.
    let identities = NodeIdentities::load(&config).unwrap();
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());

    crate::fixtures::place_covid_staging_into_inbox(&inbox, ID, CATALOG);
    std::fs::write(
        inbox.join(format!("{ID}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();
    runtime.scan_once().await;
    poll_until(Duration::from_secs(15), || {
        state
            .cache
            .get(ID)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    await_ingest_quiescent(&runtime).await;
    assert!(data_dir.join(ID).is_dir(), "the dataset ingested to disk");

    // The operator writes a `hide` override directly to the store, which is what
    // `dataset hide` does, and no SIGUSR1 is delivered.
    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    write_file(
        &sub,
        ID,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "embargo".into(),
            at: String::new(),
        },
    )
    .unwrap();

    // Drive the periodic safety-net path alone.
    runtime.full_reload().await;

    assert_eq!(
        state.cache.get(ID).unwrap().state,
        DatasetState::Hidden,
        "the periodic full_reload safety net must re-read the suppression store from \
         disk (not just re-apply the already-loaded, stale set) and hide a dataset \
         suppressed against a live node — this is the design's <= one poll fallback"
    );

    // Escalate to a `take-down` (Remove) on the same store and the same no-signal path, and
    // confirm the periodic reload also completes the evict-and-erase.
    write_file(
        &sub,
        ID,
        &Suppression {
            mode: SuppressMode::Remove,
            reason: "consent withdrawn".into(),
            at: String::new(),
        },
    )
    .unwrap();
    runtime.full_reload().await;

    assert!(
        state.cache.get(ID).is_none(),
        "the periodic reload must also re-read and complete a Remove: cache evicted"
    );
    assert!(
        state.status.lock().unwrap().get(ID).is_none(),
        "and the status entry purged"
    );
    assert!(
        !data_dir.join(ID).exists(),
        "and data_dir/{{id}}/ erased from disk"
    );
}

// ---------------------------------------------------------------------------
// `AppState::reload_and_enforce_overrides` is the unconditional override-reconcile
// timer's body (`main::spawn_override_reconcile_timer`), spawned only on a node with
// no `[service].inbox`. `spawn_rescan_timer`, which drives `full_reload`, is spawned
// only in the `Some(inbox)` arm of `main`, so a bucket-only node has no periodic
// re-read of a live override write outside boot and a best-effort `SIGUSR1`.
// ---------------------------------------------------------------------------

/// A `hide` written against a live, bucket-owned dataset on a node with no inbox configured,
/// so `IngestRuntime::full_reload`'s periodic path never runs, is still honoured. The same
/// reload-and-enforce bundle the unconditional timer calls is driven directly here, with no
/// `SIGUSR1` and no direct `reload_suppressions` or `enforce_suppressions` call.
/// `state_with_published_dataset` constructs no S3 monitor or object store, so the fallback
/// demonstrably needs no bucket poll.
#[tokio::test]
async fn reload_and_enforce_overrides_hides_a_suppressed_dataset_with_no_inbox_configured() {
    let (state, _tmp) = state_with_published_dataset(ID, "s3:provider-bucket");
    assert_eq!(state.cache.get(ID).unwrap().state, DatasetState::Visible);
    assert!(
        state.config.service.inbox.is_none(),
        "this must be a bucket/disk-only node: no inbox configured — the scenario \
         `full_reload`'s periodic path never runs for"
    );

    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    write_file(
        &sub,
        ID,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "embargo".into(),
            at: String::new(),
        },
    )
    .unwrap();

    state.reload_and_enforce_overrides().await;

    assert_eq!(
        state.cache.get(ID).unwrap().state,
        DatasetState::Hidden,
        "the unconditional override-reconcile path must re-read the suppression \
         store from disk and hide a dataset suppressed against a live, inbox-less node"
    );
}

/// The same fallback for the node-local metadata-overlay override: a `dataset correct`
/// written against a live, inbox-less, bucket-owned dataset is applied by
/// `reload_and_enforce_overrides` alone.
#[tokio::test]
async fn reload_and_enforce_overrides_applies_a_node_local_overlay_with_no_inbox_configured() {
    let (state, _tmp) = state_with_published_dataset(ID, "s3:provider-bucket");
    assert!(state.config.service.inbox.is_none());

    let patch = title_patch("Corrected via the unconditional override-reconcile timer");
    gdi_node_standalone::correct_cmd::correct(&state.config, ID, &patch, None).unwrap();

    state.reload_and_enforce_overrides().await;

    let entry = state.cache.get(ID).unwrap();
    assert_eq!(
        entry.metadata.title,
        LocalizedText::Plain("Corrected via the unconditional override-reconcile timer".to_owned()),
        "the unconditional override-reconcile path must re-read the node-local \
         overlay store from disk and apply it against a live, inbox-less node"
    );
    assert!(entry.metadata_modified.is_some());
    assert!(state.overlay_error(ID).is_none());
}

// ---------------------------------------------------------------------------
// Node-local metadata-overlay override (`dataset correct` / `--reset`)
// ---------------------------------------------------------------------------

/// Build an `AppState` with a dataset already `Visible` in the cache and on disk
/// (`data_dir/{id}/manifest.json`). Unlike [`state_with_visible_dataset`], the on-disk
/// manifest is required, because the overlay engine's `apply` and `revert`
/// (`core::overlay_store`) read the package baseline from disk on every call rather than from
/// the cache. `channel` is caller-chosen so a test can seed a bucket-owned dataset (any
/// non-`"inbox"` channel) with no S3 monitor or object store constructed, which shows the
/// overlay needs no bucket write.
fn state_with_published_dataset(id: &str, channel: &str) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let override_dir = tmp.path().join("overrides");
    let ds_dir = data_dir.join(id);
    std::fs::create_dir_all(&ds_dir).unwrap();

    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
override_dir = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        override_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();

    let manifest = manifest_for(id, CATALOG, 1);
    std::fs::write(
        ds_dir.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let mut index = StatusIndex::new();
    index.insert(
        id.to_owned(),
        StatusEntry {
            state: DatasetState::Visible,
            error_message: None,
            channel: channel.to_owned(),
            last_seen_signature: None,
            provenance: DatasetProvenance::Unknown,
        },
    );

    let state = AppState::new(config, index, NodeIdentities::empty());
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        DatasetEntry {
            id: id.to_owned(),
            metadata: manifest.metadata,
            config: manifest.config,
            state: DatasetState::Visible,
            metadata_modified: None,
        },
    );

    (state, tmp)
}

fn title_patch(title: &str) -> MetadataOverlay {
    serde_json::from_str(&format!(r#"{{"title":"{title}"}}"#)).unwrap()
}

/// A node-local override applies through the existing overlay engine on a bucket-owned
/// dataset with no bucket write. The test seeds `channel = "s3:provider-bucket"` and never
/// constructs an object store or bucket monitor, so the mechanism cannot depend on one. It
/// mirrors the `SIGUSR1` pathway (`reload_local_overlays` then `enforce_local_overlays`),
/// as the suppression tests above drive `reload_suppressions` and `enforce_suppressions`.
#[tokio::test]
async fn node_local_overlay_applies_to_a_bucket_owned_dataset_with_no_bucket_write() {
    let (state, _tmp) = state_with_published_dataset(ID, "s3:provider-bucket");
    assert!(state.cache.get(ID).unwrap().metadata_modified.is_none());

    let patch = title_patch("Corrected via node-local override");
    gdi_node_standalone::correct_cmd::correct(&state.config, ID, &patch, None).unwrap();

    // The SIGUSR1 pathway.
    state.reload_local_overlays();
    state.enforce_local_overlays();

    let entry = state.cache.get(ID).unwrap();
    assert_eq!(
        entry.metadata.title,
        LocalizedText::Plain("Corrected via node-local override".to_owned()),
        "the bucket dataset's served metadata must reflect the node-local patch"
    );
    assert!(
        entry.metadata_modified.is_some(),
        "overlay_applied_at (metadata_modified) must be set"
    );
    assert!(state.overlay_error(ID).is_none());
}

/// `dataset correct <id> --reset` removes the node-local override, and the dataset reverts to
/// the package baseline on the node's next reconcile, here the inbox scan's
/// `reconcile_overlay_reverts`. The precedence-skip guard stands down once the override file
/// is gone, so the normal revert-on-absence path resumes. This id has no source
/// `{id}.metadata.json` sidecar, so the result is the baseline rather than a source value.
#[tokio::test]
async fn correct_reset_reverts_to_baseline_on_the_next_reconcile() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let override_dir = tmp.path().join("overrides");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
override_dir = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        inbox.display(),
        override_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();

    let identities = NodeIdentities::load(&config).unwrap();
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());

    crate::fixtures::place_covid_staging_into_inbox(&inbox, ID, CATALOG);
    std::fs::write(
        inbox.join(format!("{ID}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();
    runtime.scan_once().await;
    poll_until(Duration::from_secs(15), || {
        state
            .cache
            .get(ID)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    await_ingest_quiescent(&runtime).await;
    let baseline_title = state.cache.get(ID).unwrap().metadata.title.clone();

    // Apply a node-local override.
    let patch = title_patch("Temporary correction");
    gdi_node_standalone::correct_cmd::correct(&state.config, ID, &patch, None).unwrap();
    state.reload_local_overlays();
    state.enforce_local_overlays();
    assert_ne!(state.cache.get(ID).unwrap().metadata.title, baseline_title);
    assert!(state.cache.get(ID).unwrap().metadata_modified.is_some());

    // `--reset`, then drive the node's normal reconcile alone, with no direct
    // `enforce_local_overlays` call: `reconcile_overlay_reverts` must revert it.
    gdi_node_standalone::correct_cmd::reset(&state.config, ID).unwrap();
    state.reload_local_overlays();
    runtime.scan_once().await;

    assert_eq!(
        state.cache.get(ID).unwrap().metadata.title,
        baseline_title,
        "removing the node-local override must revert the dataset to its package \
         baseline on the next reconcile"
    );
}

/// A corrupted override file must not un-redact the dataset it was redacting.
///
/// The disclosure case: an operator redacts identifiable metadata a provider published in
/// error, and a partial write, truncated restore or full disk leaves that override file
/// unparseable. If the store dropped the id, it would release the operator-over-source
/// precedence, and `reconcile_overlay_reverts` would revert the id to its source metadata,
/// re-publishing the data the override existed to withhold while the state oracle still
/// reported `overlay_error: null`.
#[tokio::test]
async fn a_corrupt_override_file_does_not_revert_the_dataset_to_its_unredacted_source() {
    let (state, runtime, _inbox, _tmp) = overlay_rig().await;
    let source_title = state.cache.get(ID).unwrap().metadata.title.clone();

    // Redact, and confirm the redaction is what is served.
    let patch = title_patch("REDACTED");
    gdi_node_standalone::correct_cmd::correct(&state.config, ID, &patch, None).unwrap();
    state.reload_local_overlays();
    state.enforce_local_overlays();
    let redacted = state.cache.get(ID).unwrap().metadata.title.clone();
    assert_ne!(
        redacted, source_title,
        "precondition: the redaction applied"
    );
    assert!(state.overlay_error(ID).is_none());

    // Truncate the override file to a single `{`, as a partial write would.
    let overlay_file = gdi_node_standalone_core::overlay_override::overlays_subdir(
        &state.config.service.override_dir_resolved(),
    )
    .join(format!("{ID}.json"));
    assert!(
        overlay_file.exists(),
        "precondition: the override file exists"
    );
    std::fs::write(&overlay_file, b"{").unwrap();

    // Drive the node's normal reconcile, which is where the revert would fire.
    state.reload_local_overlays();
    runtime.scan_once().await;

    assert_eq!(
        state.cache.get(ID).unwrap().metadata.title,
        redacted,
        "a corrupt override must keep the last-good REDACTED metadata served; reverting \
         to the source re-publishes the identifiable data the operator withheld"
    );
    assert_eq!(
        state.overlay_error(ID).as_deref(),
        Some("parse"),
        "the state oracle must report the degraded store — an auditor consults it, and \
         reporting healthy while the store is broken is what made this silent"
    );
}

/// A node with an inbox, one ingested-and-visible COVID dataset, ready for overlay tests.
/// Returns `(state, runtime, inbox, tmp)`; keep `tmp` alive for the test's duration.
async fn overlay_rig() -> (
    AppState,
    IngestRuntime,
    std::path::PathBuf,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let override_dir = tmp.path().join("overrides");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
override_dir = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        inbox.display(),
        override_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();
    let identities = NodeIdentities::load(&config).unwrap();
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());

    crate::fixtures::place_covid_staging_into_inbox(&inbox, ID, CATALOG);
    std::fs::write(
        inbox.join(format!("{ID}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();
    runtime.scan_once().await;
    poll_until(Duration::from_secs(15), || {
        state
            .cache
            .get(ID)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    await_ingest_quiescent(&runtime).await;
    (state, runtime, inbox, tmp)
}

/// The absent-EHDS advisory must reach the operator on every path.
///
/// Ingest logs it (`core::ingest`), and the overlay channels (inbox, S3, and node-local
/// `enforce_local_overlays`) all funnel through `adopt_applied_overlay`. If that funnel
/// dropped `Applied.warnings`, an operator overlay that removed the ELI would warn nowhere.
/// The funnel is shared, so driving the node-local channel (`correct_cmd::correct`,
/// `reload_local_overlays`, `enforce_local_overlays`) exercises all three.
///
/// A plain `#[test]` over a current-thread runtime, matching the other
/// `tracing::subscriber::with_default` capture tests in this suite: the capture is
/// thread-local, so the apply must run on the thread it is installed on.
#[test]
fn an_overlay_that_drops_the_ehds_eli_warns_the_operator() {
    use tracing_subscriber::layer::SubscriberExt as _;

    crate::fixtures::ensure_capture_safe_tracing();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (state, _runtime, _inbox, _tmp) = rt.block_on(overlay_rig());

    // An overlay that replaces `applicableLegislation` with a list lacking the EHDS ELI. The
    // overlay field replaces rather than merges the list, so the merged result lacks the ELI
    // whatever the rig's baseline carries.
    let patch: MetadataOverlay = serde_json::from_str(
        r#"{"applicableLegislation":["http://data.europa.eu/eli/reg/2016/679/oj"]}"#,
    )
    .unwrap();
    gdi_node_standalone::correct_cmd::correct(&state.config, ID, &patch, None).unwrap();

    let writer = test_util::CaptureWriter::new();
    let make = {
        let w = writer.clone();
        move || w.clone()
    };
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().json().with_writer(make));

    // The SIGUSR1 pathway, the one funnel every overlay channel takes.
    tracing::subscriber::with_default(subscriber, || {
        state.reload_local_overlays();
        state.enforce_local_overlays();
    });

    assert!(
        state.overlay_error(ID).is_none(),
        "precondition: the overlay must apply cleanly (a warning, not a rejection)"
    );
    let logs = writer.contents();
    assert!(
        logs.contains("metadata overlay advisory at apply"),
        "the overlay advisory must be logged at apply; logs:\n{logs}"
    );
    assert!(
        logs.contains(&gdi_node_standalone_core::validate_pkg::ehds_absent_warning()),
        "the advisory must name the absent EHDS ELI; logs:\n{logs}"
    );
    assert!(
        logs.contains("\"level\":\"WARN\""),
        "advisories are warnings, not notes; logs:\n{logs}"
    );
}

/// An inbox that cannot be read must not be mistaken for an inbox that is empty.
///
/// `scan_inbox` returns an empty result on a `read_dir` failure, such as a transient
/// permissions or mount problem, and `reconcile_overlay_reverts` treats every id missing from
/// that result as "the operator removed its sidecar". One unreadable scan would then revert
/// every inbox-owned metadata correction at once. The S3 side gates removals on a marker
/// change rather than on absence; the inbox scan must be equally unwilling to act on an
/// absence it never observed.
#[tokio::test]
async fn an_unreadable_inbox_does_not_revert_overlays() {
    let (state, runtime, inbox, _tmp) = overlay_rig().await;
    let baseline_title = state.cache.get(ID).unwrap().metadata.title.clone();

    // A source-authored inbox overlay, applied by a normal scan.
    let patch = title_patch("Source correction");
    std::fs::write(
        inbox.join(format!(
            "{ID}{}",
            gdi_node_standalone_core::overlay_store::OVERLAY_SUFFIX
        )),
        serde_json::to_vec(&patch).unwrap(),
    )
    .unwrap();
    runtime.scan_once().await;
    await_ingest_quiescent(&runtime).await;
    let corrected = state.cache.get(ID).unwrap().metadata.title.clone();
    assert_ne!(
        corrected, baseline_title,
        "sanity: the inbox overlay applied"
    );

    // The inbox becomes unreadable (mount lost, or permissions), so the scan observes
    // nothing: not because nothing is there, but because it could not look.
    std::fs::remove_dir_all(&inbox).unwrap();
    runtime.scan_once().await;

    assert_eq!(
        state.cache.get(ID).unwrap().metadata.title,
        corrected,
        "a scan that could not read the inbox must not revert corrections it never saw"
    );
}

/// An invalid node-local overlay, one that fails gdi-metadata validation once merged, is
/// rejected: the served metadata is unchanged and `overlay_error` surfaces the rejection
/// rather than the correction being dropped silently. This is the same "invalid, so ignored,
/// keeping last-good" contract a bad source sidecar gets.
///
/// A patch touching a protected field (`datasetId`, `catalog`, `numberOfRecords`) is rejected
/// one layer earlier, at parse time by `MetadataOverlay`'s `deny_unknown_fields`, before a
/// file is written; see `correct_cmd`'s `a_protected_field_is_rejected_at_build_time`. This
/// test covers the node-side reject path for a patch that parses but fails validation once
/// merged.
#[tokio::test]
async fn an_invalid_node_local_overlay_is_rejected_and_keeps_last_good() {
    let (state, _tmp) = state_with_published_dataset(ID, "s3:provider-bucket");
    let baseline_title = state.cache.get(ID).unwrap().metadata.title.clone();

    // An empty title fails gdi-metadata validation once merged, mirroring
    // `overlay_store::apply_rejects_an_invalid_merge`. Planted directly (see
    // `plant_invalid_overlay`), because `correct_cmd` refuses to write it.
    let bad: MetadataOverlay = serde_json::from_str(r#"{"title":""}"#).unwrap();
    plant_invalid_overlay(&state.config, ID, &bad);
    state.reload_local_overlays();
    state.enforce_local_overlays();

    let entry = state.cache.get(ID).unwrap();
    assert_eq!(
        entry.metadata.title, baseline_title,
        "an invalid node-local overlay must keep the last-good served metadata"
    );
    assert!(
        entry.metadata_modified.is_none(),
        "a rejected overlay must not set overlay_applied_at"
    );
    assert_eq!(
        state.overlay_error(ID).as_deref(),
        Some("validate"),
        "overlay_error must surface the rejection (C-1)"
    );
}

/// Write an override file straight to disk, bypassing `correct_cmd`'s patch validation.
///
/// `correct_cmd::correct` validates before writing, so it cannot produce an override the node
/// will reject, which is the state the two tests below need. Such a file is still reachable in
/// production: hand-edited, written by an older build, or valid alone and invalid after the
/// merge. Bypassing the CLI tests the node rather than a fiction.
fn plant_invalid_overlay(config: &ServiceConfig, id: &str, patch: &MetadataOverlay) {
    let dir = gdi_node_standalone_core::overlay_override::overlays_subdir(
        &config.service.override_dir_resolved(),
    );
    gdi_node_standalone_core::overlay_override::write_file(&dir, id, patch)
        .expect("planting the override file");
}

/// `dataset correct <id> --reset` clears a stale `overlay_error` even with no durable overlay
/// to revert.
///
/// An invalid node-local overlay records `overlay_error`, as the test above proves, but
/// because validation failed the apply wrote no durable overlay. So
/// `reconcile_overlay_reverts`'s `read_durable`-gated revert has nothing to find. Clearing the
/// stale error is `reload_local_overlays`'s job (see its doc), not the revert path's.
#[tokio::test]
async fn reset_clears_a_stale_overlay_error_left_by_a_failed_validation() {
    let (state, _tmp) = state_with_published_dataset(ID, "s3:provider-bucket");
    let baseline_title = state.cache.get(ID).unwrap().metadata.title.clone();

    let bad: MetadataOverlay = serde_json::from_str(r#"{"title":""}"#).unwrap();
    plant_invalid_overlay(&state.config, ID, &bad);
    state.reload_local_overlays();
    state.enforce_local_overlays();
    assert_eq!(
        state.overlay_error(ID).as_deref(),
        Some("validate"),
        "sanity check: the invalid overlay must record overlay_error before the reset"
    );
    assert!(
        gdi_node_standalone_core::overlay_store::read_durable(&state.config.service.data_dir, ID)
            .is_none(),
        "an invalid overlay must never be durably applied — proving the fix cannot be \
         riding on the read_durable-gated revert path"
    );

    gdi_node_standalone::correct_cmd::reset(&state.config, ID).unwrap();
    // The node's next reconcile. On a node with no inbox, as here, this is what the
    // unconditional override-reconcile timer runs.
    state.reload_and_enforce_overrides().await;

    assert!(
        state.overlay_error(ID).is_none(),
        "--reset must clear a stale overlay_error even with no durable overlay to revert \
         (the oracle, GET /datasets/{{id}}/state, reads this same overlay_error field)"
    );
    assert_eq!(
        state.cache.get(ID).unwrap().metadata.title,
        baseline_title,
        "and the dataset keeps serving its correct baseline metadata throughout"
    );
}

/// A node-local overlay takes precedence over a bucket or inbox `{id}.metadata.json` sidecar
/// for the same id: operator over source. Once applied, the override survives a subsequent
/// reconcile even while the source sidecar is still present and unchanged, so the
/// precedence-skip guard in `reconcile_overlay` and `reconcile_overlay_reverts` holds on every
/// pass rather than only the first.
#[tokio::test]
async fn node_local_overlay_wins_over_an_inbox_sidecar() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let override_dir = tmp.path().join("overrides");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
override_dir = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        inbox.display(),
        override_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();

    let identities = NodeIdentities::load(&config).unwrap();
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());

    crate::fixtures::place_covid_staging_into_inbox(&inbox, ID, CATALOG);
    std::fs::write(
        inbox.join(format!("{ID}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();
    runtime.scan_once().await;
    poll_until(Duration::from_secs(15), || {
        state
            .cache
            .get(ID)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    await_ingest_quiescent(&runtime).await;

    // Drop a source-authored sidecar and confirm the baseline mechanism works, before
    // proving the node-local override beats it.
    std::fs::write(
        inbox.join(format!("{ID}.metadata.json")),
        br#"{"title":"Source-authored title"}"#,
    )
    .unwrap();
    runtime.scan_once().await;
    poll_until(Duration::from_secs(15), || {
        state.cache.get(ID).unwrap().metadata.title
            == LocalizedText::Plain("Source-authored title".to_owned())
    })
    .await;

    // Now write a node-local override with a different title and apply it.
    let patch = title_patch("Operator-authored title");
    gdi_node_standalone::correct_cmd::correct(&state.config, ID, &patch, None).unwrap();
    state.reload_local_overlays();
    state.enforce_local_overlays();
    assert_eq!(
        state.cache.get(ID).unwrap().metadata.title,
        LocalizedText::Plain("Operator-authored title".to_owned())
    );

    // Run another inbox scan with the source sidecar still present and unchanged.
    // Precedence must hold: the node-local override still governs.
    runtime.scan_once().await;
    assert_eq!(
        state.cache.get(ID).unwrap().metadata.title,
        LocalizedText::Plain("Operator-authored title".to_owned()),
        "the node-local override must win over the inbox sidecar even on a subsequent scan"
    );
    assert!(
        inbox.join(format!("{ID}.metadata.json")).exists(),
        "the source sidecar is untouched — the node never writes it back (operator-owned)"
    );
}

// ---------------------------------------------------------------------------
// Channel-level suppression: the `inbox` channel
// ---------------------------------------------------------------------------

fn inbox_channel_config(data_dir: &Path, inbox: &Path, override_dir: &Path) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
override_dir = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        inbox.display(),
        override_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();
    config
}

#[tokio::test]
async fn preemptive_channel_suppression_blocks_inbox_ingest() {
    // A `channel-inbox.json` override authored before any package for `ID` is presented.
    // `inbox` is a channel like any other, so this blocks ingest as an id-level suppression
    // would, with no id-level file present.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let override_dir = tmp.path().join("overrides");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }
    let config = inbox_channel_config(&data_dir, &inbox, &override_dir);

    let sub = suppressions_subdir(&config.service.override_dir_resolved());
    write_channel_file(
        &sub,
        "inbox",
        &Suppression {
            mode: SuppressMode::Remove,
            reason: "provider compromised".into(),
            at: String::new(),
        },
    )
    .unwrap();

    crate::fixtures::place_covid_staging_into_inbox(&inbox, ID, CATALOG);
    std::fs::write(
        inbox.join(format!("{ID}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    // `AppState::new` loads the suppression store (the boot behaviour), so the gate is
    // armed before the very first scan.
    let identities = NodeIdentities::load(&config).unwrap();
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());
    runtime.scan_once().await;
    await_ingest_quiescent(&runtime).await;

    assert!(
        state.cache.get(ID).is_none(),
        "a channel-suppressed inbox id must never enter the served cache"
    );
    assert!(
        state.status.lock().unwrap().get(ID).is_none(),
        "and never acquire a status entry"
    );
    assert!(
        !data_dir.join(ID).exists(),
        "and no dataset dir may be materialised for it"
    );
}

#[tokio::test]
async fn channel_show_resumes_inbox_ingest() {
    // `channel show` removes `channel-inbox.json` and reloads, resuming ingest on the next
    // scan. The inbox counterpart of `channel_show_resumes_s3_ingest`.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let override_dir = tmp.path().join("overrides");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }
    let config = inbox_channel_config(&data_dir, &inbox, &override_dir);

    let sub = suppressions_subdir(&config.service.override_dir_resolved());
    write_channel_file(
        &sub,
        "inbox",
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "provider compromised".into(),
            at: String::new(),
        },
    )
    .unwrap();

    crate::fixtures::place_covid_staging_into_inbox(&inbox, ID, CATALOG);
    std::fs::write(
        inbox.join(format!("{ID}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    let identities = NodeIdentities::load(&config).unwrap();
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());
    runtime.scan_once().await;
    await_ingest_quiescent(&runtime).await;
    assert!(
        state.cache.get(ID).is_none(),
        "sanity: blocked while the inbox channel is suppressed"
    );

    // `channel show`: remove the override and reload, which is the SIGUSR1 reload point.
    remove_channel_file(&sub, "inbox").unwrap();
    state.reload_suppressions();

    runtime.scan_once().await;
    poll_until(Duration::from_secs(15), || {
        state
            .cache
            .get(ID)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    await_ingest_quiescent(&runtime).await;
}

// ---------------------------------------------------------------------------
// Targeted bucket reingest (`dataset reingest <id>` marker):
// `AppState::process_reingest_requests` and `clear_reingest_signature`, driven
// directly over the SIGUSR1 and periodic-override-reconcile path with no S3 monitor
// or object store constructed. `s3_reconcile::reingest` covers the end-to-end path
// through a real `BucketMonitor::reconcile`.
// ---------------------------------------------------------------------------

/// Build an `AppState` with a status-index-only entry for `id` on `channel`, with
/// `last_seen_signature` from `signature` and state from `dataset_state`. There is no cache
/// entry and no on-disk manifest, because `process_reingest_requests` and
/// `clear_reingest_signature` operate on the status index alone.
fn state_with_status_entry(
    id: &str,
    channel: &str,
    signature: Option<&str>,
    dataset_state: DatasetState,
) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let override_dir = tmp.path().join("overrides");
    let state = build_state(
        id,
        channel,
        signature,
        dataset_state,
        tmp.path(),
        &override_dir,
    );
    (state, tmp)
}

/// A node with its own private `data_dir` but an override store at the caller's path. Two
/// calls with the same `override_dir` model two replicas sharing one store while keeping
/// their per-replica state separate, which is the shape reingest markers must survive.
fn state_sharing_overrides(
    id: &str,
    channel: &str,
    signature: Option<&str>,
    dataset_state: DatasetState,
    override_dir: &std::path::Path,
) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let state = build_state(
        id,
        channel,
        signature,
        dataset_state,
        tmp.path(),
        override_dir,
    );
    (state, tmp)
}

fn build_state(
    id: &str,
    channel: &str,
    signature: Option<&str>,
    dataset_state: DatasetState,
    root: &std::path::Path,
    override_dir: &std::path::Path,
) -> AppState {
    let data_dir = root.join("data");
    let override_dir = override_dir.to_path_buf();
    std::fs::create_dir_all(&data_dir).unwrap();

    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
override_dir = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        override_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();

    let mut index = StatusIndex::new();
    index.insert(
        id.to_owned(),
        StatusEntry {
            state: dataset_state,
            error_message: (dataset_state == DatasetState::Error)
                .then_some(gdi_node_standalone_core::error::ErrorClass::UnknownCatalog),
            channel: channel.to_owned(),
            last_seen_signature: signature.map(ToOwned::to_owned),
            provenance: DatasetProvenance::Unknown,
        },
    );

    AppState::new(config, index, NodeIdentities::empty())
}

/// The core mechanism: a pending marker for a bucket-channel id clears its recorded
/// signature and is itself removed once processed. It is one-shot, not a durable override.
#[tokio::test]
async fn reingest_marker_clears_signature_for_a_bucket_id_and_keeps_the_marker() {
    let (state, _tmp) = state_with_status_entry(
        ID,
        "s3:provider-bucket",
        Some(r#""etag-1""#),
        DatasetState::Error,
    );
    let dir = reingest_request::requests_subdir(&state.config.service.override_dir_resolved());
    reingest_request::write_marker(&dir, ID).unwrap();

    state.process_reingest_requests().await;

    assert_eq!(
        state
            .status
            .lock()
            .unwrap()
            .get(ID)
            .unwrap()
            .last_seen_signature,
        None,
        "the recorded signature must be cleared so the S3 reconcile no longer sees the \
         package as unchanged"
    );
    assert!(
        dir.join(format!("{ID}.json")).exists(),
        "a processed marker must SURVIVE: deleting it consumed the request on behalf of \
         every other node reading the same override store"
    );
}

/// A marker naming an id the node has no status entry for at all (never seen, already
/// erased, or a plain typo) must not panic — harmless.
#[tokio::test]
async fn reingest_marker_for_an_unknown_id_is_a_harmless_no_op() {
    let (state, _tmp) = state_with_status_entry(
        "SOME-OTHER-ID-0000000000000",
        "primary",
        None,
        DatasetState::Error,
    );
    let dir = reingest_request::requests_subdir(&state.config.service.override_dir_resolved());
    // ID has no status entry in this state.
    reingest_request::write_marker(&dir, ID).unwrap();

    state.process_reingest_requests().await; // must not panic

    assert!(
        dir.join(format!("{ID}.json")).exists(),
        "a marker for an unknown id survives like any other"
    );
}

/// An `inbox`-channel entry's signature is left untouched. Reingest for the inbox channel is
/// the artifact-move mechanism (`dataset_cmd::reingest`), not a signature clear: the inbox
/// ingest gate never consults `last_seen_signature` for an absent or errored id, so clearing
/// it would gain nothing and risks a spurious "immutable-redrop" flag on a live id.
#[tokio::test]
async fn reingest_marker_skips_an_inbox_channel_entry() {
    let (state, _tmp) = state_with_status_entry(ID, "inbox", Some(r#""sig""#), DatasetState::Error);
    let dir = reingest_request::requests_subdir(&state.config.service.override_dir_resolved());
    reingest_request::write_marker(&dir, ID).unwrap();

    state.process_reingest_requests().await;

    assert_eq!(
        state
            .status
            .lock()
            .unwrap()
            .get(ID)
            .unwrap()
            .last_seen_signature
            .as_deref(),
        Some(r#""sig""#),
        "an inbox-channel entry's signature must be left untouched"
    );
    assert!(
        dir.join(format!("{ID}.json")).exists(),
        "the marker survives even though nothing was cleared"
    );
}

/// A live (`Visible`) bucket entry's signature is also left untouched. Reingest is the retry
/// mechanism for an errored dataset, not a way to force a re-download of one already being
/// served. The case is reachable when an operator runs `dataset reingest <id>` on an id that
/// turns out to be fine, or when an id self-heals to `Visible` between the marker being
/// written and processed. Clearing the signature there would only trigger the "ignored:
/// dataset is immutable; re-presented package not re-ingested" warning from
/// `s3::apply_package`'s live branch on the next reconcile.
#[tokio::test]
async fn reingest_marker_skips_a_live_bucket_entry() {
    let (state, _tmp) = state_with_status_entry(
        ID,
        "s3:provider-bucket",
        Some(r#""etag-live""#),
        DatasetState::Visible,
    );
    let dir = reingest_request::requests_subdir(&state.config.service.override_dir_resolved());
    reingest_request::write_marker(&dir, ID).unwrap();

    state.process_reingest_requests().await;

    assert_eq!(
        state
            .status
            .lock()
            .unwrap()
            .get(ID)
            .unwrap()
            .last_seen_signature
            .as_deref(),
        Some(r#""etag-live""#),
        "a live dataset's signature must be left untouched — reingest only retries an \
         ERRORED bucket dataset"
    );
    assert!(
        dir.join(format!("{ID}.json")).exists(),
        "the marker survives even though nothing was cleared"
    );
}

/// The fan-out property, and the reason processing does not delete the marker: a second node
/// reading the same override store must observe the same request independently.
///
/// If processing deleted the marker, whichever node polled first would remove it and every
/// other one would go on serving the stale dataset with nothing logged, because
/// `remove_marker` treats an already-absent file as success. Two `AppState`s over one override
/// dir is the multi-replica shape.
#[tokio::test]
async fn a_second_node_observes_a_marker_the_first_has_already_processed() {
    let (first, _tmp) = state_with_status_entry(
        ID,
        "s3:provider-bucket",
        Some(r#""etag-1""#),
        DatasetState::Error,
    );
    let override_dir = first.config.service.override_dir_resolved();
    let dir = reingest_request::requests_subdir(&override_dir);
    reingest_request::write_marker(&dir, ID).unwrap();

    first.process_reingest_requests().await;
    assert_eq!(
        first
            .status
            .lock()
            .unwrap()
            .get(ID)
            .unwrap()
            .last_seen_signature,
        None,
        "precondition: the first node cleared its own signature"
    );

    // A distinct node with its own status index, pointed at the same override store.
    let (second, _tmp2) = state_sharing_overrides(
        ID,
        "s3:provider-bucket",
        Some(r#""etag-1""#),
        DatasetState::Error,
        &override_dir,
    );

    second.process_reingest_requests().await;

    assert_eq!(
        second
            .status
            .lock()
            .unwrap()
            .get(ID)
            .unwrap()
            .last_seen_signature,
        None,
        "the second node must clear its OWN signature from the same marker; if it does \
         not, it keeps short-circuiting on the unchanged ETag and serves the stale dataset"
    );
}

/// A single node must not re-act on a marker it has already handled. Otherwise the marker
/// re-fires on every periodic pass forever, waking the reconcile trigger each time. That is
/// the cost of keeping the marker instead of deleting it, and this is what bounds it.
#[tokio::test]
async fn reprocessing_an_unchanged_marker_is_a_no_op() {
    let (state, _tmp) = state_with_status_entry(
        ID,
        "s3:provider-bucket",
        Some(r#""etag-1""#),
        DatasetState::Error,
    );
    let dir = reingest_request::requests_subdir(&state.config.service.override_dir_resolved());
    reingest_request::write_marker(&dir, ID).unwrap();

    state.process_reingest_requests().await;
    // Re-arm the signature: if the second pass acted, it would clear this again.
    {
        let mut status = state.status.lock().unwrap();
        let entry = status.get(ID).unwrap().clone();
        status.insert(
            ID.to_owned(),
            gdi_node_standalone_core::cache::StatusEntry {
                last_seen_signature: Some(r#""etag-2""#.to_owned()),
                ..entry
            },
        );
    }

    state.process_reingest_requests().await;

    assert_eq!(
        state
            .status
            .lock()
            .unwrap()
            .get(ID)
            .unwrap()
            .last_seen_signature
            .as_deref(),
        Some(r#""etag-2""#),
        "an unchanged marker must not be acted on twice by the same process"
    );
}

/// Re-requesting the same id re-arms it on every node: `write_marker` moves the
/// `requested_at` stamp, which is what "already handled" is compared against.
#[tokio::test]
async fn rewriting_a_marker_re_arms_an_already_processed_request() {
    let (state, _tmp) = state_with_status_entry(
        ID,
        "s3:provider-bucket",
        Some(r#""etag-1""#),
        DatasetState::Error,
    );
    let dir = reingest_request::requests_subdir(&state.config.service.override_dir_resolved());
    reingest_request::write_marker(&dir, ID).unwrap();
    state.process_reingest_requests().await;

    {
        let mut status = state.status.lock().unwrap();
        let entry = status.get(ID).unwrap().clone();
        status.insert(
            ID.to_owned(),
            gdi_node_standalone_core::cache::StatusEntry {
                last_seen_signature: Some(r#""etag-2""#.to_owned()),
                ..entry
            },
        );
    }
    // A fresh operator request for the same id, written directly rather than via
    // `write_marker` so the new stamp is explicit. Deriving it from the clock would make the
    // test depend on two `now_rfc3339()` calls landing in different subseconds.
    std::fs::write(
        dir.join(format!("{ID}.json")),
        br#"{"requested_at":"2030-01-01T00:00:00Z"}"#,
    )
    .unwrap();

    state.process_reingest_requests().await;

    assert_eq!(
        state
            .status
            .lock()
            .unwrap()
            .get(ID)
            .unwrap()
            .last_seen_signature,
        None,
        "a re-issued request must be acted on again"
    );
}

/// Safe to call with no pending markers at all (the periodic path's common case).
#[tokio::test]
async fn processing_reingest_requests_with_no_markers_is_a_safe_no_op() {
    let (state, _tmp) =
        state_with_status_entry(ID, "primary", Some(r#""etag""#), DatasetState::Error);
    state.process_reingest_requests().await; // must not panic
    assert_eq!(
        state
            .status
            .lock()
            .unwrap()
            .get(ID)
            .unwrap()
            .last_seen_signature
            .as_deref(),
        Some(r#""etag""#),
        "nothing to process -> nothing changes"
    );
}

/// `dataset reingest <id>` writes a marker that `process_reingest_requests` then clears
/// through, tying the CLI entry point to the node-side mechanism without a real
/// `BucketMonitor`. With no inbox configured, the CLI always takes the bucket-marker path.
/// See `s3_reconcile::reingest` for the end-to-end path through a real reconcile.
#[tokio::test]
async fn dataset_cmd_reingest_writes_a_marker_that_the_node_processes() {
    let (state, _tmp) = state_with_status_entry(
        ID,
        "s3:provider-bucket",
        Some(r#""etag-2""#),
        DatasetState::Error,
    );
    assert!(state.config.service.inbox.is_none());

    gdi_node_standalone::dataset_cmd::reingest(&state.config, ID).unwrap();
    let dir = reingest_request::requests_subdir(&state.config.service.override_dir_resolved());
    assert!(dir.join(format!("{ID}.json")).is_file());

    state.process_reingest_requests().await;

    assert_eq!(
        state
            .status
            .lock()
            .unwrap()
            .get(ID)
            .unwrap()
            .last_seen_signature,
        None
    );
    assert!(
        dir.join(format!("{ID}.json")).exists(),
        "the marker survives processing so any other node reading this store sees the \
         same request"
    );
}

/// Drive a plaintext staging-dir drop (no crypt4gh envelope, so no writer key) into an inbox
/// whose channel has a non-empty allow-list, under `policy`. Returns the state the node
/// settled on.
async fn run_plaintext_drop(policy: &str) -> (tempfile::TempDir, AppState, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let keys = tmp.path().join("keys");
    for d in [&data_dir, &inbox, &keys] {
        std::fs::create_dir_all(d).unwrap();
    }

    // The node has an identity, so `enforce` is coherent; it is the artifact that carries
    // none.
    let (node_sk, _node_pk) = generate_keypair();
    let identity_file = keys.join("node.c4gh");
    write_identity(&identity_file, &node_sk);

    // The drop: a plaintext staging dir straight into the inbox. No envelope, so there is no
    // writer fingerprint to check against the allow-list.
    build_covid_staging_goe(&inbox, ID);
    std::fs::write(
        inbox.join(format!("{ID}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    // A non-empty allow-list naming a different writer, which is the posture `enforce`
    // forces the operator into.
    let allowed = public_key_fingerprint(&generate_keypair().1);
    let config = policy_config(&data_dir, &inbox, &identity_file, &allowed, policy);
    let identities = NodeIdentities::load(&config).unwrap();
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());
    runtime.scan_once().await;
    await_ingest_quiescent(&runtime).await;
    // `tmp` is returned, not dropped: the caller inspects paths under it.
    (tmp, state, inbox)
}

/// A plaintext drop carries no writer key, so it can never be allow-listed, yet `enforce`
/// requires every channel to have an allow-list. If an unidentified staging dir published
/// anyway, the staging-dir path would be the one input that walks past the control the
/// operator was forced to configure. It fails closed instead.
#[tokio::test]
async fn enforce_quarantines_an_unidentified_plaintext_drop() {
    let (_tmp, state, inbox) = run_plaintext_drop("enforce").await;

    poll_until(Duration::from_secs(15), || {
        let status = state.status.lock().unwrap();
        status
            .get(ID)
            .is_some_and(|e| e.state == DatasetState::Error)
    })
    .await;
    {
        let status = state.status.lock().unwrap();
        assert_eq!(
            status.get(ID).unwrap().error_message,
            Some(gdi_node_standalone_core::error::ErrorClass::WriterRejected),
            "an unidentified plaintext drop is a permanent writer-rejected error under enforce"
        );
    }
    assert!(
        inbox.join(".rejected").join(ID).exists(),
        "the plaintext drop must be quarantined, not published"
    );
    assert!(
        !state
            .cache
            .get(ID)
            .is_some_and(|e| e.state == DatasetState::Visible),
        "an unidentified plaintext drop must never be served under enforce"
    );
}

/// `warn` is the discovery mode: the same drop still publishes, so an operator can find every
/// plaintext producer before switching to `enforce` and breaking them.
#[tokio::test]
async fn warn_still_publishes_a_plaintext_drop() {
    let (_tmp, state, _inbox) = run_plaintext_drop("warn").await;

    poll_until(Duration::from_secs(15), || {
        state
            .cache
            .get(ID)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    let status = state.status.lock().unwrap();
    assert_eq!(
        status.get(ID).unwrap().error_message,
        None,
        "warn records the plaintext drop but must not reject it"
    );
}

// ---------------------------------------------------------------------------------------
// The override-store "used" marker under the operator CLI.
// ---------------------------------------------------------------------------------------

/// A config for driving the operator CLI verbs directly: `data_dir`, where the "used" marker
/// lives, and `override_dir`, both under `tmp`, with no inbox and no buckets.
fn override_cli_config(tmp: &Path, require_override_store: bool) -> ServiceConfig {
    let data_dir = tmp.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
override_dir = "{}"
require_override_store = {require_override_store}

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        tmp.join("overrides").display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();
    config
}

/// The "used" marker is what distinguishes a structure-only-restored store (every withhold
/// gone, directories intact) from a node that never held an override. A lift that removed
/// nothing is not evidence that this node emptied its own store, so it leaves the marker
/// standing. Otherwise an operator "cleaning up" with a verb that changed nothing disarms the
/// boot refusal the marker exists for. The sequence here is hide, lose the files, no-op
/// unhide, boot.
#[test]
fn a_no_op_unhide_does_not_disarm_the_used_marker() {
    use gdi_node_standalone::override_marker::{marker_path, sync_and_assert};
    use gdi_node_standalone::suppress_cmd::{hide, show};

    const OTHER: &str = "GDI-EE-UTARTU-20260409143052999";

    let tmp = tempfile::tempdir().unwrap();
    let config = override_cli_config(tmp.path(), true);
    let marker = marker_path(&config);

    // 1. `dataset hide X`: the marker is set.
    hide(&config, ID, "erasure request").unwrap();
    assert!(marker.exists(), "a hide sets the USED marker");

    // 2. Lose every override file but keep the directory tree: the structure-only restore
    //    shape. The marker survives on the data volume, and boot refuses.
    let sub = suppressions_subdir(&config.service.override_dir_resolved());
    for entry in std::fs::read_dir(&sub).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    assert!(
        marker.exists(),
        "the marker is on the DATA volume and survives"
    );
    sync_and_assert(&config, true).expect_err("an emptied store under the marker must refuse");

    // 3. `dataset unhide <id with no override>`: a supported, audited no-op. It removed
    //    nothing, so it is no evidence this node emptied the store; the marker stands and
    //    the boot still refuses.
    show(&config, OTHER, "tidying up").unwrap();
    assert!(
        marker.exists(),
        "a no-op unhide removed nothing and must not clear the USED marker"
    );
    sync_and_assert(&config, true)
        .expect_err("the boot refusal must survive an operator's no-op unhide");

    // The control: a real lift of the last remaining override is the node emptying its own
    // store, and only that clears the marker so the next boot passes.
    hide(&config, ID, "re-hide").unwrap();
    assert!(marker.exists());
    show(&config, ID, "consent re-granted").unwrap();
    assert!(
        !marker.exists(),
        "lifting the last override clears the marker (a legitimately emptied store boots)"
    );
    sync_and_assert(&config, true).expect("an attested-empty store boots");
}

/// The runtime twin of the boot refusal. `reload_suppressions` fails closed when the loader
/// directory is absent. A present-but-empty directory is the structure-only restore shape,
/// every file gone and the tree intact, and loading it as the empty set would lift every
/// withhold including `Remove` take-downs. The "used" marker distinguishes that shape from a
/// legitimately emptied store, so a reload that finds the store empty under the marker keeps
/// the last-good set, as the absent arm does.
#[tokio::test]
async fn reload_keeps_suppressions_when_the_store_is_emptied_under_the_marker() {
    use gdi_node_standalone::override_marker::{marker_path, sync};

    for require_override_store in [true, false] {
        let (state, _tmp) = state_with_visible_dataset_opts(ID, require_override_store);
        let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
        write_file(
            &sub,
            ID,
            &Suppression {
                mode: SuppressMode::Remove,
                reason: "erasure request".into(),
                at: String::new(),
            },
        )
        .unwrap();
        sync(&state.config);
        assert!(
            marker_path(&state.config).exists(),
            "the write set the marker"
        );
        state.reload_suppressions();
        assert!(
            state
                .suppressions
                .read()
                .unwrap()
                .effective(ID, "inbox")
                .is_some(),
            "sanity: the take-down loaded"
        );

        // The loss: every override file is gone and the directory tree survives. The loader
        // dir is present, so the absent-store arm cannot see this.
        for entry in std::fs::read_dir(&sub).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        state.reload_suppressions();

        assert!(
            state
                .suppressions
                .read()
                .unwrap()
                .effective(ID, "inbox")
                .is_some(),
            "require_override_store={require_override_store}: a store emptied under the \
             USED marker while the node is withholding must NOT be adopted — the last-good \
             set survives, as it does for an absent store"
        );
    }
}

/// The false-refusal control for the test above: a store emptied by a CLI lift of the last
/// override is legitimately empty, because the lift cleared the marker. The next reload adopts
/// the empty set normally, so the lifted dataset is not withheld until a restart.
#[tokio::test]
async fn a_store_emptied_by_a_cli_lift_adopts_the_empty_set_on_reload() {
    use gdi_node_standalone::override_marker::marker_path;
    use gdi_node_standalone::suppress_cmd::{hide, show};

    let (state, _tmp) = state_with_visible_dataset_opts(ID, true);
    hide(&state.config, ID, "embargo").unwrap();
    assert!(marker_path(&state.config).exists());
    state.reload_suppressions();
    assert!(
        state
            .suppressions
            .read()
            .unwrap()
            .effective(ID, "inbox")
            .is_some(),
        "sanity: the hide loaded"
    );

    show(&state.config, ID, "embargo lifted").unwrap();
    assert!(
        !marker_path(&state.config).exists(),
        "the lift of the last override cleared the marker"
    );
    state.reload_suppressions();
    assert!(
        state
            .suppressions
            .read()
            .unwrap()
            .effective(ID, "inbox")
            .is_none(),
        "a store the CLI emptied is adopted normally — no false refusal"
    );
}

/// Overlay twin of `reload_keeps_suppressions_when_the_store_is_emptied_under_the_marker`:
/// adopting an emptied overlay set drops every operator>source precedence claim and the
/// next reconcile re-publishes the metadata each correction was redacting.
#[tokio::test]
async fn reload_keeps_local_overlays_when_the_store_is_emptied_under_the_marker() {
    use gdi_node_standalone::override_marker::{marker_path, sync};

    for require_override_store in [true, false] {
        let (state, _tmp) = state_with_visible_dataset_opts(ID, require_override_store);
        let dir = gdi_node_standalone_core::overlay_override::overlays_subdir(
            &state.config.service.override_dir_resolved(),
        );
        gdi_node_standalone_core::overlay_override::write_file(&dir, ID, &title_patch("t"))
            .unwrap();
        sync(&state.config);
        assert!(marker_path(&state.config).exists());
        state.reload_local_overlays();
        assert!(state.local_overlays.read().unwrap().contains(ID));

        for entry in std::fs::read_dir(&dir).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        state.reload_local_overlays();

        assert!(
            state.local_overlays.read().unwrap().contains(ID),
            "require_override_store={require_override_store}: an overlay store emptied \
             under the USED marker must not revert the corrections this node is serving"
        );
    }
}

/// Overlay twin of `a_store_emptied_by_a_cli_lift_adopts_the_empty_set_on_reload`.
#[tokio::test]
async fn an_overlay_store_emptied_by_a_cli_reset_adopts_the_empty_set_on_reload() {
    use gdi_node_standalone::correct_cmd::reset;
    use gdi_node_standalone::override_marker::{marker_path, sync};

    let (state, _tmp) = state_with_visible_dataset_opts(ID, true);
    let dir = gdi_node_standalone_core::overlay_override::overlays_subdir(
        &state.config.service.override_dir_resolved(),
    );
    gdi_node_standalone_core::overlay_override::write_file(&dir, ID, &title_patch("t")).unwrap();
    sync(&state.config);
    state.reload_local_overlays();
    assert!(state.local_overlays.read().unwrap().contains(ID));

    reset(&state.config, ID).unwrap();
    assert!(
        !marker_path(&state.config).exists(),
        "the reset of the last override cleared the marker"
    );
    state.reload_local_overlays();
    assert!(
        !state.local_overlays.read().unwrap().contains(ID),
        "an overlay store the CLI emptied is adopted normally — no false refusal"
    );
}

/// An id-level take-down of an id that was never ingested. Nothing is under `data_dir`,
/// nothing is cached and nothing is in the status index, so neither erase walk in
/// `enforce_suppressions` reaches it. The provider's drop is still in the inbox, because
/// `consider_artifact` leaves a suppressed drop in place, which leaves the subject's data on
/// the node's volume indefinitely. A take-down is an erasure request, so it must reach it.
#[tokio::test]
async fn take_down_of_a_never_ingested_id_erases_its_inbox_drop() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }
    let config = inbox_channel_config(&data_dir, &inbox, &tmp.path().join("overrides"));
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());

    let drop_file = inbox.join(format!("{ID}.tar.c4gh"));
    std::fs::write(&drop_file, b"ciphertext").unwrap();
    assert!(!data_dir.join(ID).exists(), "precondition: never ingested");

    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    write_file(
        &sub,
        ID,
        &Suppression {
            mode: SuppressMode::Remove,
            reason: "erasure request".into(),
            at: String::new(),
        },
    )
    .unwrap();
    state.reload_suppressions();
    state.enforce_suppressions().await;

    assert!(
        !drop_file.exists(),
        "a take-down of a never-ingested id must erase its inbox drop"
    );
}
