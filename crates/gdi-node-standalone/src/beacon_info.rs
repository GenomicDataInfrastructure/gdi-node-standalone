//! The Beacon v2 informational and static surface: entry types and mount scoping,
//! `/info` and `/service-info`, `/configuration`, `/entry_types`, `/map`,
//! `/filtering_terms`, and the `/.well-known/c4gh-recipient` endpoint.
//!
//! [`crate::beacon_http`] keeps the query path (`g_variants`, `datasets`,
//! `individuals`) and the shared `error_response`. These handlers are self-contained:
//! they render config-derived JSON and never touch the query/parquet path.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use gdi_node_standalone_core::config::{BeaconConfig, ServiceConfig};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::beacon_http::default_model_base;
use crate::state::AppState;

/// Insert `key => value` into `obj` only when `value` is `Some`, the omit-when-absent
/// shape every optional field in these documents shares. The wire carries no `null`
/// for an unset field.
fn insert_opt<T: Serialize>(obj: &mut Map<String, Value>, key: &str, value: Option<&T>) {
    if let Some(v) = value {
        obj.insert(key.to_owned(), json!(v));
    }
}

// ---- Entry types + mount scope ----

/// A Beacon v2 entry type this node serves.
///
/// The three entry types map onto the two mount prefixes: `GenomicVariant` and
/// `Dataset` live under the aggregated prefix, `Individual` under the sensitive
/// prefix; a combined mount serves all three. Each variant carries the static facts
/// the informational endpoints render (id, name, endpoint, ontology term, schema
/// folder), so adding one more entry type is a one-arm change here plus a route in
/// [`crate::app`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryType {
    /// `genomicVariant` — the aggregated allele-frequency query (`g_variants`).
    GenomicVariant,
    /// `dataset` — the `beaconCollectionsResponse` collections (`datasets`).
    Dataset,
    /// `individual` — the sensitive-beacon placeholder (`individuals`).
    Individual,
}

impl EntryType {
    /// The entry type's stable id (the `entryTypes` map key and `/map` key).
    fn id(self) -> &'static str {
        match self {
            Self::GenomicVariant => "genomicVariant",
            Self::Dataset => "dataset",
            Self::Individual => "individual",
        }
    }

    /// The human-readable name.
    fn name(self) -> &'static str {
        match self {
            Self::GenomicVariant => "Genomic Variant",
            Self::Dataset => "Dataset",
            Self::Individual => "Individual",
        }
    }

    /// The query endpoint path segment (the route under the mount prefix).
    fn endpoint(self) -> &'static str {
        match self {
            Self::GenomicVariant => "g_variants",
            Self::Dataset => "datasets",
            Self::Individual => "individuals",
        }
    }

    /// The default-schema id (`/entry_types` + `/configuration`).
    fn default_schema_id(self) -> &'static str {
        match self {
            Self::GenomicVariant => "ga4gh-beacon-variant-v2.0.0",
            Self::Dataset => "ga4gh-beacon-dataset-v2.0.0",
            Self::Individual => "ga4gh-beacon-individual-v2.0.0",
        }
    }

    /// The default-schema human name.
    fn default_schema_name(self) -> &'static str {
        match self {
            Self::GenomicVariant => "Default schema for a genomic variant",
            Self::Dataset => "Default schema for a dataset",
            Self::Individual => "Default schema for an individual",
        }
    }

    /// The folder under `beacon-v2-default-model` holding the entry type's schema.
    fn schema_folder(self) -> &'static str {
        match self {
            Self::GenomicVariant => "genomicVariations",
            Self::Dataset => "datasets",
            Self::Individual => "individuals",
        }
    }

    /// The pinned `ontologyTermForThisType` `(id, label)` for each entry type: an
    /// Ensembl Glossary term for the genomic variant, NCI Thesaurus terms for the
    /// dataset and individual.
    fn ontology_term(self) -> (&'static str, &'static str) {
        match self {
            Self::GenomicVariant => ("ENSGLOSSARY:0000092", "Variant"),
            Self::Dataset => ("NCIT:C47824", "Data set"),
            Self::Individual => ("NCIT:C25190", "Individual"),
        }
    }

    /// Whether the node serves a `GET /{endpoint}/{id}` single-entry route.
    ///
    /// The node serves none, so `/map` omits `singleEntryUrl` for every entry type.
    /// Flipping an arm to `true` when its single-entry route lands also makes `/map`
    /// emit that entry type's `singleEntryUrl`.
    fn has_single_entry(self) -> bool {
        match self {
            Self::GenomicVariant | Self::Dataset | Self::Individual => false,
        }
    }

    /// The mount prefix this entry type's `/map` `rootUrl` is built from.
    ///
    /// On a split mount the aggregated entry types resolve to the aggregated prefix
    /// and the individual to the sensitive prefix; on a combined mount both prefixes
    /// are equal, so the choice is moot.
    fn mount_prefix(self, cfg: &BeaconConfig) -> &str {
        match self {
            Self::Individual => &cfg.sensitive_base_path,
            Self::GenomicVariant | Self::Dataset => &cfg.aggregated_base_path,
        }
    }
}

/// Which entry types a mounted prefix serves.
///
/// `Aggregated` and `Sensitive` are the split layout, the default, since the default
/// prefixes differ; `Combined` is the single mount used when both prefixes are set
/// equal. The scope drives the per-prefix scoping of `/entry_types`,
/// `/configuration.entryTypes`, and `/map.endpointSets`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MountScope {
    /// `genomicVariant` + `dataset`.
    Aggregated,
    /// `individual` only.
    Sensitive,
    /// All three: the combined mount, used when both prefixes are set equal.
    Combined,
}

impl MountScope {
    /// The entry type whose schema this mount's synthesized resilience errors name
    /// (`414`, `408`, `503`, `500`, raised outside the routed mounts, where there is no
    /// endpoint to ask). The aggregated and combined mounts name `genomicVariant`, the
    /// node's primary entry type, as `beacon_http::error_response` does; the sensitive
    /// mount names `individual`, the only entry type it serves.
    ///
    /// The unmatched-path `404` does not use this: it carries an empty `returnedSchemas`
    /// (`beacon_http::route_miss_response`), so `crate::app`'s `error_dialect` is the
    /// only caller.
    pub(crate) fn primary_entry_type(self) -> &'static str {
        match self {
            Self::Aggregated | Self::Combined => EntryType::GenomicVariant.id(),
            Self::Sensitive => EntryType::Individual.id(),
        }
    }

    /// The entry types this scope serves, in a stable order.
    fn entry_types(self) -> &'static [EntryType] {
        match self {
            Self::Aggregated => &[EntryType::GenomicVariant, EntryType::Dataset],
            Self::Sensitive => &[EntryType::Individual],
            Self::Combined => &[
                EntryType::GenomicVariant,
                EntryType::Dataset,
                EntryType::Individual,
            ],
        }
    }
}

// ---- Informational endpoints ----

/// The `beaconInformationalResponseMeta` for the `{meta,response}` envelope.
fn informational_meta(cfg: &BeaconConfig) -> Value {
    json!({
        "beaconId": cfg.id,
        "apiVersion": cfg.api_version,
        "returnedSchemas": [],
    })
}

/// Wrap an inner `response` object in the Beacon v2 `{meta, response}` envelope.
fn wrap(cfg: &BeaconConfig, response: &Value) -> Response {
    let envelope = json!({
        "meta": informational_meta(cfg),
        "response": response,
    });
    (StatusCode::OK, Json(envelope)).into_response()
}

/// The `organization` sub-object shared by `/info`.
fn organization_object(cfg: &BeaconConfig) -> Value {
    let org = &cfg.organization;
    let mut obj = Map::new();
    obj.insert("id".to_owned(), json!(org.id));
    obj.insert("name".to_owned(), json!(org.name));
    insert_opt(&mut obj, "description", org.description.as_ref());
    insert_opt(&mut obj, "welcomeUrl", org.welcome_url.as_ref());
    insert_opt(&mut obj, "contactUrl", org.contact_url.as_ref());
    insert_opt(&mut obj, "logoUrl", org.logo_url.as_ref());
    Value::Object(obj)
}

/// `BeaconInfo` inner response for `/` and `/info`.
fn beacon_info_response(cfg: &ServiceConfig) -> Value {
    let b = &cfg.beacon;
    let mut obj = Map::new();
    obj.insert("id".to_owned(), json!(b.id));
    obj.insert("name".to_owned(), json!(b.name));
    obj.insert("apiVersion".to_owned(), json!(b.api_version));
    obj.insert("environment".to_owned(), json!(b.environment));
    obj.insert("organization".to_owned(), organization_object(b));
    obj.insert("welcomeUrl".to_owned(), json!(cfg.service.base_url));
    insert_opt(&mut obj, "description", b.description.as_ref());
    insert_opt(&mut obj, "version", b.version.as_ref());
    insert_opt(&mut obj, "alternativeUrl", b.alternative_url.as_ref());
    insert_opt(&mut obj, "createDateTime", b.created_at.as_ref());
    insert_opt(&mut obj, "updateDateTime", b.updated_at.as_ref());
    Value::Object(obj)
}

/// `GET {prefix}/` and `GET {prefix}/info` — `BeaconInfo` in the `{meta,response}` envelope.
pub(crate) async fn info(State(state): State<AppState>) -> Response {
    wrap(&state.config.beacon, &beacon_info_response(&state.config))
}

/// `GET {prefix}/service-info` — the bare GA4GH `ServiceInfo` (the only un-wrapped one).
pub(crate) async fn service_info(State(state): State<AppState>) -> Response {
    let cfg = &state.config;
    let b = &cfg.beacon;
    let mut obj = Map::new();
    obj.insert("id".to_owned(), json!(b.id));
    obj.insert("name".to_owned(), json!(b.name));
    obj.insert(
        "type".to_owned(),
        json!({
            "group": "org.ga4gh",
            "artifact": "beacon",
            "version": b.api_version,
        }),
    );
    obj.insert(
        "organization".to_owned(),
        json!({
            "name": b.organization.name,
            // GA4GH service-info `organization.url` is the organization's website, the
            // same semantics as Beacon `welcomeUrl`, which `/info` sources from
            // `welcome_url`. Prefer the configured website; fall back to the service
            // base_url only to satisfy the required field when it is unset.
            "url": b.organization.welcome_url.as_deref().unwrap_or(cfg.service.base_url.as_str()),
        }),
    );
    obj.insert("environment".to_owned(), json!(b.environment));
    // `version` is required by the GA4GH service-info schema. When `[beacon].version`
    // is unset, fall back to the running binary version (`CARGO_PKG_VERSION`) so the
    // default deploy still serves a conformant service-info that a Service Registry or
    // Beacon-Network aggregator accepts. An explicit config value overrides.
    obj.insert(
        "version".to_owned(),
        json!(b.version.as_deref().unwrap_or(env!("CARGO_PKG_VERSION"))),
    );
    insert_opt(&mut obj, "description", b.description.as_ref());
    insert_opt(&mut obj, "contactUrl", b.organization.contact_url.as_ref());
    insert_opt(&mut obj, "documentationUrl", b.documentation_url.as_ref());
    (StatusCode::OK, Json(Value::Object(obj))).into_response()
}

/// Build one entry type's `entryTypeDefinition` object (`/entry_types` +
/// `/configuration.entryTypes`).
fn entry_type_definition(entry: EntryType, api_version: &str) -> Value {
    let base = default_model_base(api_version);
    let (term_id, term_label) = entry.ontology_term();
    json!({
        "id": entry.id(),
        "name": entry.name(),
        "partOfSpecification": "Beacon v2.2.0",
        "defaultSchema": {
            "id": entry.default_schema_id(),
            "name": entry.default_schema_name(),
            "referenceToSchemaDefinition": format!(
                "{base}/{}/defaultSchema.json", entry.schema_folder()
            )
        },
        "ontologyTermForThisType": { "id": term_id, "label": term_label }
    })
}

/// Build the `entryTypes` map for a mount's scope.
fn entry_types_map(scope: MountScope, api_version: &str) -> Value {
    let mut map = Map::new();
    for entry in scope.entry_types() {
        map.insert(
            entry.id().to_owned(),
            entry_type_definition(*entry, api_version),
        );
    }
    Value::Object(map)
}

/// `GET {prefix}/map` — `BeaconMap` of endpointSets for this mount's scope.
///
/// Each entry type's `rootUrl` is `{base_url}{prefix}/{endpoint}`, where `prefix` is
/// the entry type's own mount prefix, aggregated or sensitive; see
/// [`EntryType::mount_prefix`]. `singleEntryUrl` is emitted only for an entry type that
/// serves a `GET /{endpoint}/{id}` route, and none do yet.
pub(crate) fn map(state: &AppState, scope: MountScope) -> Response {
    let cfg = &state.config;
    let beacon = &cfg.beacon;
    let base = &cfg.service.base_url;

    let mut endpoint_sets = Map::new();
    for entry in scope.entry_types() {
        let prefix = entry.mount_prefix(beacon);
        let mut set = Map::new();
        set.insert("entryType".to_owned(), json!(entry.id()));
        set.insert(
            "rootUrl".to_owned(),
            json!(format!("{base}{prefix}/{}", entry.endpoint())),
        );
        if entry.has_single_entry() {
            set.insert(
                "singleEntryUrl".to_owned(),
                json!(format!("{base}{prefix}/{}/{{id}}", entry.endpoint())),
            );
        }
        endpoint_sets.insert(entry.id().to_owned(), Value::Object(set));
    }

    let response = json!({
        "$schema": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/v2.2.0/framework/json/configuration/beaconMapSchema.json",
        "endpointSets": Value::Object(endpoint_sets)
    });
    wrap(beacon, &response)
}

/// `GET {prefix}/entry_types` — the mount's entry types in the `{meta,response}`
/// envelope.
pub(crate) fn entry_types(state: &AppState, scope: MountScope) -> Response {
    let beacon = &state.config.beacon;
    let response = json!({ "entryTypes": entry_types_map(scope, &beacon.api_version) });
    wrap(beacon, &response)
}

/// `GET {prefix}/configuration` — `BeaconConfiguration` in the `{meta,response}`
/// envelope.
///
/// `entryTypes` is scoped to the mount; `maturityAttributes.productionStatus` and
/// `securityAttributes` (`defaultGranularity` + `securityLevels: [PUBLIC]`) come
/// from `[beacon.configuration]`.
pub(crate) fn configuration(state: &AppState, scope: MountScope) -> Response {
    let beacon = &state.config.beacon;
    let conf = &beacon.configuration;
    let response = json!({
        "$schema": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/v2.2.0/framework/json/configuration/beaconConfigurationSchema.json",
        "entryTypes": entry_types_map(scope, &beacon.api_version),
        "maturityAttributes": { "productionStatus": conf.production_status },
        "securityAttributes": {
            "defaultGranularity": conf.default_granularity,
            "securityLevels": [conf.security_level]
        }
    });
    wrap(beacon, &response)
}

/// `GET {prefix}/filtering_terms` — empty list: the aggregated beacon does no filtering,
/// and the sensitive mount advertises an empty list too.
pub(crate) async fn filtering_terms(State(state): State<AppState>) -> Response {
    wrap(&state.config.beacon, &json!({ "filteringTerms": [] }))
}

// ---- Well-known endpoints (public plane) ----

/// `GET /.well-known/c4gh-recipient` — the node's crypt4gh recipient.
///
/// Returns the public key of the first configured `[keys].identities` entry,
/// serialized as the crypt4gh PEM, as `text/plain`. A provider, and the
/// `gdi-dataset-tool` via `node_recipient_url`, fetches this to encrypt a package to
/// the node. Only the public recipient is served, never a secret. A keyless node with
/// no identities configured disables the endpoint and returns `404`.
///
/// The recipient is public material, so this endpoint serves on the public listener.
pub(crate) async fn c4gh_recipient(State(state): State<AppState>) -> Response {
    match state.identities.recipient_pem() {
        Some(pem) => {
            // A short, stable fingerprint in a response header lets a re-wrapping
            // operator confirm the key without diffing the PEM body; the body stays the
            // raw PEM, which is machine-parsed.
            let fingerprint = gdi_node_standalone_core::crypt4gh::parse_public_key(&pem)
                .map(|pk| gdi_node_standalone_core::crypt4gh::public_key_fingerprint(&pk))
                .unwrap_or_default();
            (
                StatusCode::OK,
                [
                    (
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; charset=utf-8".to_owned(),
                    ),
                    (
                        axum::http::HeaderName::from_static("x-c4gh-recipient-fingerprint"),
                        fingerprint,
                    ),
                ],
                pem,
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "no crypt4gh recipient configured").into_response(),
    }
}
