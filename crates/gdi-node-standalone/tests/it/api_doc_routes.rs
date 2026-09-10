//! Doc-vs-code route-presence guard for the repo's `docs/api.md` HTTP reference.
//!
//! It runs in two directions, so the doc and the router cannot silently drift. Forward
//! (`every_documented_endpoint_is_served`): every path documented in `docs/api.md` is routed
//! by the live `build_router` / `build_management_router`. Reverse
//! (`every_app_route_is_documented`): every route literal declared in `app.rs` /
//! `metrics.rs` appears in `docs/api.md`.
//!
//! The forward check probes the real router in-process with a method no route allows
//! (`DELETE`), which proves a path is routed independent of handler behaviour: a registered
//! path answers `405 Method Not Allowed`, an unregistered one falls through to `404`. Every
//! public fallback answers `404` and the management plane has none, so a non-`404` status
//! means the path is served.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::{build_management_router, build_router};
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::{DatasetProvenance, StatusEntry, StatusIndex};
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::state::DatasetState;
use tower::ServiceExt as _; // for `oneshot`

/// The repo-root docs + main router source, embedded at compile time (paths are
/// relative to this file: `tests/it/` → repo root is four levels up).
const API_MD: &str = include_str!("../../../../docs/api.md");
const APP_RS: &str = include_str!("../../src/app.rs");
const METRICS_RS: &str = include_str!("../../src/metrics.rs");

/// Must equal `[beacon].aggregated_base_path` (and `sensitive_base_path`) in the
/// config below. The default layout is split; this guard pins a combined mount so the
/// documented `/beacon/v2/{g_variants,individuals,…}` routes are all served on one
/// endpoint and the doc-vs-code check stays path-stable.
const BEACON_PREFIX: &str = "/beacon/v2";

/// The prefixes a relative route literal may be nested under: the beacon sub-router at
/// `BEACON_PREFIX` and the FDP sub-router at `/fairdp` (see `every_app_route_is_documented`).
const NEST_PREFIXES: &[&str] = &[BEACON_PREFIX, "/fairdp"];

/// `/metrics` is gated on a process-global Prometheus recorder
/// (`metrics::install_recorder`, installed once per process) and is exercised
/// behaviourally in `metrics_endpoint.rs`; the management router built here has no
/// recorder handle, so the forward probe skips it (the reverse/documentation check
/// still requires it to be documented).
const FORWARD_PROBE_SKIP: &[&str] = &["/metrics"];

#[derive(Clone, Copy)]
enum Plane {
    Public,
    Management,
}

/// A lite (keyless / no-S3 / no-Vault) service config rooted at `data_dir`.
fn lite_config(data_dir: &std::path::Path) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
# Every OPT-IN surface is on here, because this file's guards ask "is everything
# docs/api.md documents actually served?". Probing a router built with the defaults
# would make an opt-in route impossible to document: it would be absent, the guard
# would fail, and the only way to green it would be to stop documenting the route —
# turning a completeness guard into pressure to under-document.
expose_dataset_list = true

[stats]
# The other opt-in management surfaces, on for the same reason as the flag above.
enabled = true

[control]
enabled = true

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "{BEACON_PREFIX}"
sensitive_base_path = "{BEACON_PREFIX}"
id = "org.test.beacon"
name = "Test Beacon"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#,
        data_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();
    config
}

/// A lite `AppState` carrying `status`, enough to build either router.
fn state_with(status: StatusIndex) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = AppState::new(lite_config(&data_dir), status, NodeIdentities::empty());
    (state, tmp)
}

/// A lite `AppState` with an empty status index.
fn minimal_state() -> (AppState, tempfile::TempDir) {
    state_with(StatusIndex::new())
}

/// Extract the first ```` ```json ```` fenced block that follows `marker` in `md`.
fn fenced_json_after_marker(md: &str, marker: &str) -> String {
    let after = md
        .split_once(marker)
        .expect("example marker present in docs/api.md")
        .1;
    let after = after
        .split_once("```json")
        .expect("a ```json fence after the marker")
        .1;
    after
        .split_once("```")
        .expect("a closing ``` fence")
        .0
        .trim()
        .to_owned()
}

/// Substitute the doc placeholders with concrete values so the path can be requested.
fn concretize(documented: &str) -> String {
    crate::route_inventory::concretize(&documented.replace("{prefix}", BEACON_PREFIX))
}

/// Extract the substrings wrapped in backticks from a markdown table cell.
fn backtick_tokens(cell: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for part in cell.split('`') {
        if inside {
            out.push(part.to_owned());
        }
        inside = !inside;
    }
    out
}

/// Parse the endpoint rows out of `docs/api.md`'s "Public plane" / "Management plane"
/// route tables: each documented path, tagged with its plane and the HTTP method(s) its
/// row lists (uppercased; a `GET, POST` cell yields `[GET, POST]`).
fn documented_endpoints() -> Vec<(Plane, String, Vec<String>)> {
    let mut out = Vec::new();
    let mut plane: Option<Plane> = None;
    for line in API_MD.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("## Public plane") {
            plane = Some(Plane::Public);
            continue;
        }
        if trimmed.starts_with("## Management plane") {
            plane = Some(Plane::Management);
            continue;
        }
        if trimmed.starts_with("##") {
            plane = None; // any other H2 ends the route-table region
            continue;
        }
        let Some(current) = plane else { continue };
        if !trimmed.starts_with('|') {
            continue;
        }
        let cols: Vec<&str> = trimmed.split('|').collect();
        if cols.len() < 3 {
            continue;
        }
        let method = cols[1].trim();
        if method.eq_ignore_ascii_case("Method") || method.starts_with("---") || method.is_empty() {
            continue; // header or separator row
        }
        let methods: Vec<String> = method
            .split(',')
            .map(|m| m.trim().to_ascii_uppercase())
            .filter(|m| !m.is_empty())
            .collect();
        for tok in backtick_tokens(cols[2]) {
            // Path tokens are absolute (`/…`) or prefixed (`{prefix}` / `{prefix}/…`).
            if tok.starts_with('/') || tok.starts_with("{prefix}") {
                out.push((current, tok, methods.clone()));
            }
        }
    }
    out
}

/// The first double-quoted string literal in `s` (route paths carry no escapes).
fn first_string_literal(s: &str) -> Option<String> {
    let after = &s[s.find('"')? + 1..];
    let end = after.find('"')?;
    Some(after[..end].to_owned())
}

#[tokio::test]
async fn every_documented_endpoint_is_served() {
    let (state, _tmp) = minimal_state();
    let public = build_router(state.clone());
    let management = build_management_router(state, None);

    let endpoints = documented_endpoints();
    assert!(
        endpoints.len() >= 15,
        "parsed only {} endpoints from docs/api.md — the table format likely changed and \
         this guard would silently pass; fix the parser",
        endpoints.len()
    );

    for (plane, documented, methods) in endpoints {
        if FORWARD_PROBE_SKIP.contains(&documented.as_str()) {
            continue;
        }
        let uri = concretize(&documented);
        let router = match plane {
            Plane::Public => &public,
            Plane::Management => &management,
        };
        // No route registers DELETE (the tables document only GET / GET,POST), so a
        // DELETE probe hits a registered path as `405 Method Not Allowed` (carrying an
        // `Allow` header) and an unregistered one as `404`.
        let req = Request::builder()
            .method("DELETE")
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "docs/api.md documents `{documented}` ({uri}) but the live router does not serve \
             it (a DELETE probe returned 404 instead of 405). Update docs/api.md or the router."
        );

        // Method verification: the 405's `Allow` header lists the methods the route
        // actually serves. Assert that set — minus the HEAD/OPTIONS axum adds
        // automatically, equals exactly the methods documented for the row, so a route
        // that drops a documented `POST` (or gains an undocumented method) fails here.
        // The path-only forward check above cannot see this.
        if status == StatusCode::METHOD_NOT_ALLOWED {
            let allow = resp
                .headers()
                .get(axum::http::header::ALLOW)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_else(|| {
                    panic!("405 for `{documented}` ({uri}) carried no Allow header")
                });
            let live: std::collections::BTreeSet<String> = allow
                .split(',')
                .map(|m| m.trim().to_ascii_uppercase())
                .filter(|m| !m.is_empty() && !matches!(m.as_str(), "HEAD" | "OPTIONS"))
                .collect();
            let documented_set: std::collections::BTreeSet<String> =
                methods.iter().cloned().collect();
            assert_eq!(
                live, documented_set,
                "method drift for `{documented}` ({uri}): docs/api.md documents \
                 {documented_set:?} but the router serves {live:?} (auto HEAD/OPTIONS \
                 excluded) — reconcile docs/api.md or the router"
            );
        }
    }
}

/// The route literals the router source declares, split by plane: the bodies of the
/// management-router functions (`build_management_router`, `management_health_router`,
/// `traced_management_router`) plus `metrics.rs` (which mounts `/metrics` on that plane)
/// are the management plane; every other literal in `app.rs`, plus the `mount_entry_type`
/// names, is public. A management route mounted from a new function would be read as
/// public here and fail against the public rows — loudly, which is the right direction.
///
/// The split matters because both planes declare a literal `/datasets`: the management
/// inventory route, and the beacon entry type nested under the beacon prefix. Reading the
/// literals plane-blind lets the public row `/beacon/v2/datasets` satisfy the management
/// literal through the nest-prefix resolution, so the management row for the route that
/// lists every dataset, hidden ones included, could go missing unnoticed.
fn app_route_literals_by_plane() -> (Vec<String>, Vec<String>) {
    fn body_of<'a>(src: &'a str, fn_marker: &str) -> &'a str {
        let start = src
            .find(fn_marker)
            .unwrap_or_else(|| panic!("{fn_marker} not found in app.rs"));
        let end = src[start..]
            .find("\n}\n")
            .map_or(src.len(), |rel| start + rel + 3);
        &src[start..end]
    }
    let production = APP_RS.split("\n#[cfg(test)]").next().unwrap_or(APP_RS);
    let management_bodies: Vec<&str> = [
        "pub fn build_management_router(",
        "fn management_health_router(",
        "fn traced_management_router(",
    ]
    .iter()
    .map(|marker| body_of(production, marker))
    .collect();
    let mut public_src = production.to_owned();
    for body in &management_bodies {
        public_src = public_src.replacen(body, "", 1);
    }
    let mut public = crate::route_inventory::all_route_literals(&[public_src.as_str()]);
    for (idx, _) in public_src.match_indices("mount_entry_type(") {
        // Call sites only: the function's own definition is followed by the `format!`
        // template `"/{entry_type}"`, which is not a route name.
        if public_src[..idx].ends_with("fn ") {
            continue;
        }
        if let Some(name) = first_string_literal(&public_src[idx..]) {
            public.push(format!("/{name}"));
        }
    }
    let mut management_sources: Vec<&str> = management_bodies.clone();
    management_sources.push(METRICS_RS);
    let management = crate::route_inventory::all_route_literals(&management_sources);
    (public, management)
}

#[test]
fn every_app_route_is_documented() {
    // A route must appear in a parsed table row, not merely somewhere in the file: a
    // substring search over the whole document is satisfied by any prose mention, so a
    // route described in a paragraph but missing from the route table would pass. A route
    // table that a sentence elsewhere can satisfy is not a route table.
    //
    // The match is also per plane: a management literal is satisfied only by a management
    // row, and the nest-prefix resolution below applies only to public literals.
    let mut public_rows: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut management_rows: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (plane, path, _) in documented_endpoints() {
        match plane {
            Plane::Public => public_rows.insert(concretize(&path)),
            Plane::Management => management_rows.insert(concretize(&path)),
        };
    }

    let (public, management) = app_route_literals_by_plane();
    // Vacuity floors: a parser that silently matched nothing would make this a guard that
    // passes by examining an empty list.
    assert!(
        public.len() >= 12 && management.len() >= 8,
        "parsed only {} public and {} management route literals from the router source — \
         the parser broke and this guard would pass by checking nothing",
        public.len(),
        management.len()
    );

    for path in &management {
        let concrete = concretize(path);
        assert!(
            management_rows.contains(&concrete),
            "`{path}` is declared on the MANAGEMENT router but has no ROW in docs/api.md's \
             management-plane route table (a public row, or a prose mention, does not \
             count). Documented management rows: {management_rows:?}"
        );
    }
    for path in &public {
        // The bare nest-root `/` is ambiguous, and `/{entry_type}` is the internal
        // mount template (its concrete names are checked via `mount_entry_type`) — matched
        // exactly, so a real route whose name merely contains the word is not skipped.
        if path == "/" || path == "/{entry_type}" {
            continue;
        }
        // A literal may be absolute, or relative to the sub-router it is declared on and
        // nested under that router's prefix (`.route("/info", …)` on the beacon router
        // mounts at `/beacon/v2/info`; `.route("/catalog/{id}", …)` on the FDP router at
        // `/fairdp/catalog/{id}`). Accept any of those resolutions — but only against a
        // real public table row, never against arbitrary prose.
        let concrete = concretize(path);
        let resolved = NEST_PREFIXES
            .iter()
            .any(|prefix| public_rows.contains(&format!("{prefix}{concrete}")));
        assert!(
            public_rows.contains(&concrete) || resolved,
            "`{path}` is declared on the PUBLIC router but has no ROW in a docs/api.md \
             public-plane route table (a prose mention elsewhere does not count). \
             Documented public rows: {public_rows:?}"
        );
    }
}

#[tokio::test]
async fn documented_dataset_state_example_matches_live_output() {
    // The `/datasets/{id}/state` example block in docs/api.md must equal what the live
    // management router actually emits, so a documented example cannot drift.
    const ID: &str = "GDI-EE-EXAMPLE-20260409143052837";

    let mut status = StatusIndex::new();
    status.insert(
        ID.to_owned(),
        StatusEntry {
            state: DatasetState::Visible,
            error_message: None,
            channel: "inbox".to_owned(),
            // Set, because every dataset the node has actually processed records one: an
            // inbox package's content hash, or an S3 object's ETag. `None` here would make
            // the documented example the one shape a real ingested dataset never has, so a
            // consumer written against it would meet an undocumented field on its first
            // live call.
            last_seen_signature: Some(
                "sha256:73ec88d6edd94412b2f35612903048abf5cac990b908d73e86fedd14757523b5"
                    .to_owned(),
            ),
            // A `.tar.c4gh` dropped into the inbox carries a crypt4gh header, so it has a
            // recovered writer fingerprint (a plaintext staging dir would not). Non-`unknown`
            // here so the documented example demonstrates the `recovered` shape and this
            // guard exercises its serialization through the live router.
            provenance: DatasetProvenance::Recovered {
                fingerprints: vec![
                    "sha256:59dea1f5d1b035cf30101bcec603973ded73f8727616b58b8912d38c66e4f022"
                        .to_owned(),
                ],
            },
        },
    );
    let (state, _tmp) = state_with(status);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/datasets/{ID}/state"))
        .body(Body::empty())
        .unwrap();
    let resp = build_management_router(state, None)
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let live: serde_json::Value = serde_json::from_slice(bytes.as_ref()).unwrap();

    let documented: serde_json::Value = serde_json::from_str(&fenced_json_after_marker(
        API_MD,
        "<!-- example:dataset-state",
    ))
    .unwrap();

    assert_eq!(
        live, documented,
        "docs/api.md's dataset-state example has drifted from live output\n  live:       {live}\n  documented: {documented}"
    );
}

#[tokio::test]
async fn documented_health_ready_example_matches_live_output() {
    // A lite node reports ready once the startup reconcile is done and key material is
    // present (keyless mode reports `key_material: ok`) — matching the documented body.
    let (state, _tmp) = state_with(StatusIndex::new());
    state.readiness.mark_initial_reconcile_done();
    state.readiness.set_key_material_ok(true);

    let req = Request::builder()
        .method("GET")
        .uri("/health/ready")
        .body(Body::empty())
        .unwrap();
    let resp = build_management_router(state, None)
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let live: serde_json::Value = serde_json::from_slice(bytes.as_ref()).unwrap();

    let documented: serde_json::Value = serde_json::from_str(&fenced_json_after_marker(
        API_MD,
        "<!-- example:health-ready",
    ))
    .unwrap();

    assert_eq!(
        live, documented,
        "docs/api.md's /health/ready example has drifted from live output\n  live:       {live}\n  documented: {documented}"
    );
}

#[tokio::test]
async fn documented_g_variants_boolean_example_matches_live_output() {
    // An empty boolean query needs no dataset: it returns a `beaconBooleanResponse`
    // with `exists: false`. The documented block must equal this live envelope.
    let (state, _tmp) = minimal_state();

    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "{BEACON_PREFIX}/g_variants?requestedGranularity=boolean"
        ))
        .body(Body::empty())
        .unwrap();
    let resp = build_router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let live: serde_json::Value = serde_json::from_slice(bytes.as_ref()).unwrap();

    let documented: serde_json::Value = serde_json::from_str(&fenced_json_after_marker(
        API_MD,
        "<!-- example:g-variants-boolean",
    ))
    .unwrap();

    assert_eq!(
        live, documented,
        "docs/api.md's g_variants boolean example has drifted from live output\n  live:       {live}\n  documented: {documented}"
    );
}

/// `docs/api.md`'s VRS 1.3 `variation` example, checked against a real `/g_variants` record
/// response rather than left as an unverified illustration: it is the block an integrator
/// copies to learn the coordinate encoding, so a drift there hands the reader a wrong
/// contract.
///
/// The fence is a JSON *fragment* (one object member, as it appears inside a `results[]`
/// entry), so it is wrapped in braces before parsing.
#[tokio::test]
async fn documented_g_variants_variation_example_matches_live_output() {
    // The COVID fixture's single variant, chr3:45823240 T>C on GRCh38 — the one the doc
    // block names.
    let (state, _tmp) = crate::beacon_query::state_with_covid();
    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": [45_823_239],
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38",
                "requestedGranularity": "RECORD"
            }
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri(format!("{BEACON_PREFIX}/g_variants"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = build_router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let live: serde_json::Value = serde_json::from_slice(bytes.as_ref()).unwrap();
    let live_variation = &live["response"]["resultSets"][0]["results"][0]["variation"];
    // Derived subject: an empty result set would make the comparison below vacuous.
    assert!(
        live_variation.is_object(),
        "the fixture query must return a record carrying a variation, or this test asserts \
         nothing: {live}"
    );

    let fragment = fenced_json_after_marker(API_MD, "<!-- example:g-variants-variation");
    let documented: serde_json::Value =
        serde_json::from_str(&format!("{{{fragment}}}")).expect("the fence is one JSON member");

    assert_eq!(
        live_variation, &documented["variation"],
        "docs/api.md's variation example has drifted from live output\n  live:       {live_variation}\n  documented: {}",
        documented["variation"]
    );
}
