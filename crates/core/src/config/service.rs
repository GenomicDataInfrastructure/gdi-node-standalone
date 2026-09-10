//! `gdi-node-standalone` service configuration ([`ServiceConfig`]) and its `preflight`
//! validation. Split out of [`super`] (the config module root) from the tool's
//! [`super::ToolConfig`]; the shared secret-`Debug` helper [`super::redacted`]
//! lives in the module root.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::validate_pkg::MAX_CATALOG_LEN;

use super::redacted;

/// Whether a catalog name is safe to embed in an FDP IRI: ASCII alphanumerics plus
/// `-_.`, at most [`MAX_CATALOG_LEN`] chars, no leading dot and no `..`. Mirrors the
/// HTTP-path `id_guard::is_safe_catalog_name`; used by [`ServiceConfig::preflight`]
/// to reject a `[catalogs]` key that would otherwise produce a malformed `/fairdp`
/// IRI via `NamedNode::new_unchecked`.
fn is_safe_catalog_name(name: &str) -> bool {
    crate::validate_pkg::is_safe_catalog_name(name)
}

/// Default config path used when neither `--config` nor `GDI_CONFIG` is set.
///
/// Named `node.toml`, not `config.toml`: the provider tool's config is also TOML, is also
/// naturally called `config.toml`, and has a disjoint schema, so a shared name lets an
/// operator running both roles in one directory feed each binary the other's file. See
/// [`ToolConfig`](super::ToolConfig)'s default file name for the other half.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/gdi-node-standalone/node.toml";

/// The GA4GH Beacon framework version this node serves and is pinned to.
///
/// `[beacon].api_version` is not a free operator knob: the informational handlers
/// hardcode `v2.2.0` `$schema` / `partOfSpecification` literals (`beacon_info.rs`), and
/// the vendored framework schemas under `conformance/ga4gh-beacon-v2/` are `v2.2.0`.
/// Preflight pins `api_version` to this value so a typo cannot make `/info` /
/// `/configuration` / `/map` advertise a schema tree that does not exist. Re-vendoring a
/// newer framework and bumping this is one deliberate change.
pub const SUPPORTED_BEACON_API_VERSION: &str = "v2.2.0";

/// The built-in default for [`FairdpConfig::language`]: the EU authority IRI for
/// English.
///
/// English is what the node's own generated strings (the Beacon distribution and
/// `DataService` titles, and the catalog titles most deployments write) are in. A node
/// publishing in another language sets its own EU `language/…` IRI; there is no
/// per-dataset override.
pub const DEFAULT_FAIRDP_LANGUAGE: &str =
    "http://publications.europa.eu/resource/authority/language/ENG";

/// The `gdi-node-standalone` service configuration (`node.toml`).
///
/// Models the service config blocks: `[service]`,
/// `[catalogs]`, `[beacon]` (+ nested `[beacon.organization]` /
/// `[beacon.configuration]`), an optional `[fairdp]` (the FAIR Data Point node
/// identity — see [`FairdpConfig`]), and the optional `[s3]` / `[vault]`
/// networked-feature config, gated by the `s3`/`vault` Cargo features (see
/// [`S3Config`] / [`VaultConfig`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceConfig {
    /// `[service]` block.
    pub service: ServiceSection,
    /// `[catalogs]`: catalog name -> display title.
    pub catalogs: BTreeMap<String, String>,
    /// `[beacon]` block (+ nested organization / configuration).
    pub beacon: BeaconConfig,
    /// `[keys]` block: the node's crypt4gh identity files. Default empty (keyless:
    /// the encrypted `.tar.c4gh` path + `/.well-known/c4gh-recipient` are disabled).
    pub keys: KeysConfig,
    /// `[audit]` block — the answered-query audit log (on by default; query content
    /// withheld by default). See [`AuditConfig`].
    pub audit: AuditConfig,
    /// `[stats]` block — the management-plane per-dataset query-statistics endpoint
    /// (off by default). See [`StatsConfig`].
    pub stats: StatsConfig,
    /// `[control]` block — the management-plane operator actions that make the node act
    /// (reload, reconcile, log level). Off by default. See [`ControlConfig`].
    pub control: ControlConfig,
    /// `[ingest]` block — the crypt4gh writer-key allow-list policy. Default `off`
    /// (record provenance, gate nothing). See [`IngestConfig`].
    pub ingest: IngestConfig,
    /// Optional `[fairdp]` block — the FAIR Data Point node identity. FDP is not
    /// required (beacon is); when present, preflight validates it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fairdp: Option<FairdpConfig>,
    /// Optional `[s3]` block — S3 bucket monitoring. Requires the `s3` Cargo
    /// feature; a config carrying `[[s3.buckets]]` on a binary built without `s3`
    /// is rejected by the service's feature preflight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3: Option<S3Config>,
    /// Optional `[vault]` block — the Vault KV/Transit client config. Requires
    /// the `vault` Cargo feature; a `transit_key` additionally requires `pme`.
    /// Rejected by the feature preflight when the feature is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<VaultConfig>,
}

/// The `[audit]` block — the answered-query audit log.
///
/// The node emits one structured `audit`-target log line per answered Beacon
/// data-discovery query (`g_variants` / `datasets` / `individuals`), for accountability.
/// It is on by default, but the query content (coordinates / filters) is withheld by
/// default (`query_detail = false`), so the default is privacy-preserving: the line
/// records that a query of a given entry type was answered, with its result granularity /
/// `exists` / count, and correlates to the request via the span's `request_id` (join to
/// the fronting proxy's access log for the client IP) — but not which variant was asked.
/// Set `query_detail = true` to also log the request parameters, only where the local
/// DPIA permits recording the queried coordinates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// Emit the per-query audit line. Default `true`.
    pub enabled: bool,
    /// Also log the request parameters — the queried coordinates / filters. Default `false`
    /// (privacy-preserving). The parameters are recorded verbatim (JSON-escaped, and bounded
    /// by `max_request_body_bytes`), not semantically sanitized: unknown keys a client sends
    /// are serialized as received. Enable only where the local DPIA permits recording the
    /// queried coordinates, and treat the audit stream as containing client-supplied content.
    pub query_detail: bool,
    /// Audit the management plane's read events too — the `dataset_state_read`,
    /// `dataset_inventory_read` and `query_stats_read` lines. Default `false`.
    ///
    /// These record an orchestrator polling the node's own oracle for reconciliation, not a
    /// disclosure to a data consumer, and an orchestrator polls per dataset per tick: at a
    /// 60 s cadence over 100 datasets that is ~144k retained lines a day, burying the
    /// disclosures the trail exists for. Off by default: the public-plane disclosure trail
    /// (`beacon_query`, `fairdp_read`) is unaffected, and the management plane's request
    /// volume stays on `gdi_http_requests_total{plane="management"}`. Turn it on where a
    /// DPIA wants the management-read trail recorded despite the volume.
    pub management_reads: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            query_detail: false,
            management_reads: false,
        }
    }
}

/// The `[stats]` block — per-dataset query statistics on the management plane.
///
/// A master switch, mirroring `[audit].enabled`, for the in-memory usage counters and the
/// `GET /stats/queries` route that serves them: how often each dataset was consulted by a
/// Beacon query, matched, appeared in a `/datasets` listing, and had its FDP record read.
///
/// Off by default, and off means absent. The counts name dataset ids, including hidden
/// ones, so they are the management plane's disclosure class rather than the metrics
/// plane's (`/metrics` labels stay content-free: never a per-dataset-id label). With this
/// `false` the route is not mounted at all, so it answers `404` and the flag itself is
/// unprobeable; nothing is counted either, so a node that did not opt in pays neither the
/// lock nor the per-dataset map.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StatsConfig {
    /// Record per-dataset query counters and serve `GET /stats/queries` on the management
    /// listener. Default `false`.
    pub enabled: bool,
}

/// The `[control]` block — operator actions on the management plane.
///
/// Everything else this plane serves is a read. These routes make the node act: re-read its
/// config, reconcile now, change its log level. That is a different kind of authority, so it
/// gets its own switch and it is off by default — the plane stays read-only unless an
/// operator opts in, as `write_status`, the loopback `management_addr` and
/// `trust_inbound_traceparent` also do.
///
/// They exist because applying a changed config otherwise needs `SIGHUP`, and the usual way
/// to send one in a cluster (`kubectl exec … kill -HUP 1`) needs `pods/exec`, which is
/// effectively shell access and is commonly withheld. The only other fallback is restarting
/// the pod, which at one replica is a public Beacon outage. None of these routes takes a
/// body, so none can inject configuration: they only tell the node to re-read its own
/// already-trusted sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ControlConfig {
    /// Serve the operator action routes on the management listener. Default `false`, and off
    /// means the routes are not mounted at all (`404`).
    pub enabled: bool,
    /// Minimum seconds between two accepted control actions; a request inside the window is
    /// refused with `429` and a `Retry-After`. Default `10`.
    ///
    /// These actions are real work — a config parse, a full reconcile — so they are paced
    /// rather than served on demand. `0` is rejected at startup: an unpaced action endpoint
    /// is not a shape this feature ships in.
    pub min_interval_seconds: u64,
    /// How long `POST /log-level` keeps diagnostic logging on before reverting on its own.
    /// Default `900` (15 minutes).
    ///
    /// The auto-revert is why the endpoint is safe to expose: `debug` left on in production
    /// is both a disk-and-cost problem and a sustained log flood an attacker could hold open,
    /// and a bounded window closes both. `0` is rejected at startup — a zero-length window
    /// would revert before the operator could read anything, and is not a way to turn the
    /// feature off (`enabled = false` is).
    pub log_level_revert_seconds: u64,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_interval_seconds: 10,
            log_level_revert_seconds: 900,
        }
    }
}

/// How the node treats a package's crypt4gh writer key at ingest.
///
/// The writer key is proof-of-possession, not an authenticated identity (anyone with the
/// node's public recipient key can author under a fresh key), so gating on it is opt-in and
/// off by default. `warn` is the discovery mode: it records which fingerprints actually
/// arrive (surfaced by the `datasets --unverified` listing and the
/// `gdi_ingest_writer_unknown_total` metric) so an operator can build the per-channel
/// allow-list before switching to `enforce`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WriterPolicy {
    /// Record provenance, gate nothing (the shipped default).
    #[default]
    Off,
    /// Publish regardless, but count and audit any artifact the channel cannot vouch for: a
    /// writer key that is not allow-listed, a header that will not parse, or a plaintext drop
    /// (which carries no writer key at all). The safe discovery mode: it shows everything
    /// `enforce` would reject, before it is turned on.
    Warn,
    /// Fail closed: an artifact the channel cannot vouch for is quarantined, not published.
    /// That is a `.tar.c4gh` whose recovered writer key is not allow-listed for its channel,
    /// one whose header will not parse, and a plaintext staging-dir drop, which carries no
    /// writer key and therefore can never be allow-listed.
    ///
    /// Gating plaintext is what makes the allow-list mean anything: `enforce` requires every
    /// ingest channel to have a non-empty allow-list (see `preflight_writer_policy`), so
    /// admitting an unidentified staging dir would leave one input path bypassing the control
    /// the operator was just required to configure. A node that legitimately ingests plaintext
    /// is a keyless node, and `enforce` on a node with no `[keys].identities` is rejected at
    /// preflight, since it could never verify a writer key.
    Enforce,
}

/// The `[ingest]` block — the crypt4gh writer-key allow-list policy.
///
/// Fingerprints are public (`sha256` of a public key), so they live in `node.toml`, not
/// Vault. The per-channel lists live on `[[s3.buckets]]` and, for the inbox, here: the trust
/// boundary is the channel, so a key legitimate for one provider cannot publish as another.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IngestConfig {
    /// How to treat a package's writer key. Default [`WriterPolicy::Off`].
    pub writer_policy: WriterPolicy,
    /// A required, non-empty acknowledgement to run `enforce` while some ingest channel has
    /// an empty allow-list (which would otherwise reject every encrypted package on that
    /// channel). Mirrors the k-anonymity `suppression_disabled_ack` posture: a deliberate,
    /// audited operator decision, not an accident. Empty (the default) makes that a
    /// boot-refusing misconfiguration.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub allow_any_writer_ack: String,
    /// Writer-key fingerprints permitted to publish via the local inbox channel. Empty by
    /// default. The bucket channels carry their own lists on
    /// `[[s3.buckets]].allowed_writer_fingerprints`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbox_allowed_writer_fingerprints: Vec<String>,
}

/// The `[s3]` block — S3 bucket monitoring, gated by the `s3` Cargo feature.
///
/// Holds the `[[s3.buckets]]` array of monitored buckets; each [`S3Bucket`]
/// carries its own endpoint, credentials, poll intervals, and writeback intent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct S3Config {
    /// The monitored buckets (`[[s3.buckets]]`). The service can monitor several
    /// at once (the tool targets one per profile).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub buckets: Vec<S3Bucket>,
}

/// One monitored S3 bucket (`[[s3.buckets]]`).
///
/// Carries the identity and endpoint, the inline credential fallback (Vault's `s3_path`,
/// keyed by `name`, takes precedence when configured), the marker/full poll intervals, and
/// the per-bucket writeback intent.
///
/// `PartialEq` is what the monitor reload diffs a running channel's descriptor against the
/// freshly-loaded one, and it must stay a field comparison rather than the `Debug` string
/// the other config diffs here use: that impl redacts `secret_access_key`, so a rotated
/// credential would compare equal and the node would keep using the stale key until a
/// restart.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct S3Bucket {
    /// Logical channel name: the provenance recorded in the status index, the key the
    /// Vault `s3_path` credentials are stored under, and the `gdi_s3_*{channel}` metric
    /// label.
    pub name: String,
    /// The S3 endpoint URL (custom endpoint for Ceph+Rook / Garage / minio).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// The bucket name on the endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// Key prefix this channel is confined to within `bucket` (e.g.
    /// `gdi-node-storage/`). Empty (the default) means the whole bucket.
    ///
    /// Every key the channel touches — the listing, the `{id}.tar.c4gh` packages, the
    /// `{id}.state.json` / `{id}.metadata.json` sidecars, `_sync_marker.json` and the
    /// `_status/` writebacks — resolves under it, so the node issues no request outside the
    /// prefix and a credential scoped to `…/<prefix>*` is sufficient. That pairing is the
    /// point: on a bucket the node shares with anything else, an unprefixed node lists, and
    /// needs read on, the whole bucket.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prefix: String,
    /// The S3 region. Unset resolves to `us-east-1`, the conventional placeholder Ceph and
    /// minio accept; Garage checks it against its configured `s3_region` (`garage` in the
    /// Compose stack) and rejects a mismatch with a 400.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Path-style addressing (Ceph/Garage/minio) rather than virtual-hosted. Default
    /// `false`.
    pub path_style: bool,
    /// Allow plain HTTP endpoints (for local minio/Garage dev). Default `false`, so a
    /// production misconfiguration cannot silently drop TLS.
    pub allow_http: bool,
    /// Inline S3 access key id (the no-Vault fallback; Vault's `s3_path` wins when
    /// configured). Optional: omitted for an anonymous/IAM endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    /// Inline S3 secret access key (the no-Vault fallback; see `access_key_id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_access_key: Option<String>,
    /// `HeadObject` poll interval for `_sync_marker.json` (seconds; default 30).
    pub marker_poll_interval: u64,
    /// Unconditional full-reconcile interval (seconds; default 300), the safety
    /// net for out-of-band changes that did not bump the marker.
    pub full_poll_interval: u64,
    /// Whether the node may publish `_status/{id}.json` ingest results back into this
    /// bucket. Default `false`. Needs a narrow `_status/*` write grant; an `AccessDenied`
    /// latches writeback off rather than failing ingest. See "Node status writeback" in
    /// `docs/package-format.md`.
    pub write_status: bool,
    /// The crypt4gh writer-key fingerprints (`sha256:<hex>`) permitted to publish into
    /// this channel, consulted under `[ingest].writer_policy`. Empty (the default) means
    /// "no allow-list for this channel". Per-channel because the trust boundary is the
    /// bucket, not the node — a key legitimate for one provider must not publish as another.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_writer_fingerprints: Vec<String>,
}

impl S3Bucket {
    /// Whether `other` addresses a different keyspace than `self` — a change to the channel's
    /// identity rather than to how it reaches the same objects.
    ///
    /// The line between the two classes is the failure mode:
    ///
    /// * Identity (`name`, `endpoint`, `bucket`, `prefix`) decides *which objects the channel
    ///   can see*. Get one wrong and the listing succeeds and returns nothing, which is
    ///   indistinguishable from "the provider deleted everything" — so the reconcile evicts,
    ///   and the datasets are deleted from disk while the channel still reports healthy.
    /// * Access (`region`, `path_style`, `allow_http`, the credentials) and behaviour (the
    ///   poll intervals, `write_status`, `allowed_writer_fingerprints`) decide *how* the
    ///   channel reaches the same objects. Get one wrong and it fails loudly — an auth or
    ///   transport error, the channel goes `unavailable`, and nothing is evicted.
    ///
    /// Only the second class is safe to hot-swap on a reload, which is what the monitor
    /// reload handles (a rotated credential). Applying the first class live destroys data, so
    /// it stays a restart-only prefix migration.
    ///
    /// The body destructures `self` exhaustively on purpose: adding a field to [`S3Bucket`]
    /// stops compiling here until someone classifies it. A `..` rest-pattern would let the
    /// next field default silently into the safe-to-hot-swap half, which is the half that
    /// deletes datasets when the guess is wrong.
    #[must_use]
    pub fn addresses_different_keyspace_than(&self, other: &Self) -> bool {
        let Self {
            name,
            // The keyspace trio — compared (and persisted) through
            // [`Self::keyspace_witness`], which is where "the keyspace" is defined. A field
            // classified into this half must be routed into the witness, or the comparison
            // below cannot see it.
            endpoint: _,
            bucket: _,
            prefix: _,
            // Access + behaviour: a mistake here fails loudly, so these hot-swap.
            region: _,
            path_style: _,
            allow_http: _,
            access_key_id: _,
            secret_access_key: _,
            marker_poll_interval: _,
            full_poll_interval: _,
            write_status: _,
            allowed_writer_fingerprints: _,
        } = self;
        *name != other.name || self.keyspace_witness() != other.keyspace_witness()
    }

    /// As [`Self::addresses_different_keyspace_than`], but ignoring `name`.
    ///
    /// The reload needs both questions. "Did this channel's keyspace move?" compares by name
    /// and includes it. "Is this newly-named entry the same keyspace some still-running
    /// channel already polls?" — a rename — must ignore the name, or every rename looks like a
    /// distinct keyspace and a second monitor starts on the same bucket.
    #[must_use]
    pub fn addresses_different_keyspace_than_ignoring_name(&self, other: &Self) -> bool {
        self.keyspace_witness() != other.keyspace_witness()
    }

    /// The name-independent identity of the keyspace this entry addresses, as the
    /// persistable [`KeyspaceWitness`].
    ///
    /// This is where "the keyspace" is defined: the name-ignoring comparison above delegates
    /// here, and the witness the monitor persists beside its datasets is constructed here, so
    /// the compared identity and the recorded identity cannot drift apart.
    #[must_use]
    pub fn keyspace_witness(&self) -> KeyspaceWitness {
        KeyspaceWitness {
            // `endpoint`/`bucket` are `Option` in the config type, but preflight
            // unconditionally rejects an entry whose endpoint or bucket is missing or
            // blank ("`endpoint` and `bucket` are unconditionally required"), so by the
            // time a monitor exists both are non-empty strings and the empty-string
            // stand-in below is unreachable — kept only so this constructor is total.
            //
            // Persisted in the wire spelling (see `KeyspaceWitness`), so the file beside
            // the datasets and the reload's twin comparison both see one keyspace where
            // the operator may have written two spellings of it.
            endpoint: wire_endpoint(self.endpoint.as_deref().unwrap_or_default()).to_owned(),
            bucket: self.bucket.clone().unwrap_or_default(),
            prefix: wire_prefix(&self.prefix).to_owned(),
        }
    }
}

/// The endpoint as `object_store` addresses it: its S3 builder joins `endpoint` and
/// `bucket` with a single `/` after trimming any trailing slashes off the endpoint, so
/// `https://s3.example.org` and `https://s3.example.org/` are one endpoint on the wire.
fn wire_endpoint(endpoint: &str) -> &str {
    endpoint.trim_end_matches('/')
}

/// The prefix as the store wrapper addresses it: [`validate_key_prefix`] accepts exactly
/// one optional trailing slash because `object_store::path::Path` drops the empty segment
/// it creates, so `a` and `a/` list the same objects. `strip_suffix`, not
/// `trim_end_matches`, for the reason given there: a run of slashes is a different
/// keyspace (and is refused before a witness is ever built).
fn wire_prefix(prefix: &str) -> &str {
    prefix.strip_suffix('/').unwrap_or(prefix)
}

/// The fully-populated [`S3Bucket`] whose serialisation is the env-overlay field set: the
/// keys of its JSON object are the fields `GDI_NODE__S3__BUCKETS__<i>__…` may set, and each
/// value's JSON type is what the override string is coerced to.
///
/// Every field must serialise to a key. `S3Bucket` applies `skip_serializing_if` to its
/// `Option`s, to `prefix` and to `allowed_writer_fingerprints`, so a `None` or an empty probe
/// value drops the field from the set and the documented override for it is refused at boot
/// as "`S3Bucket` has no such field" — a silently unsettable field. The struct literal makes
/// a new field a compile error here until it is listed;
/// `the_s3_env_probe_exposes_every_bucket_field` makes an empty probe value a test failure.
pub(super) fn s3_bucket_env_probe() -> S3Bucket {
    S3Bucket {
        name: String::new(),
        endpoint: Some(String::new()),
        bucket: Some(String::new()),
        prefix: String::from("x"),
        region: Some(String::new()),
        access_key_id: Some(String::new()),
        secret_access_key: Some(String::new()),
        path_style: false,
        allow_http: false,
        write_status: false,
        marker_poll_interval: 0,
        full_poll_interval: 0,
        allowed_writer_fingerprints: vec![String::new()],
    }
}

/// The keyspace a channel's on-disk datasets were ingested from: `endpoint` + `bucket` +
/// `prefix` — the trio [`S3Bucket::addresses_different_keyspace_than`] classifies as
/// restart-only because applying a change live cannot be told from a mass deletion.
///
/// Persisted by the bucket monitor as `data_dir/.keyspace-{channel}.json`, kept beside the
/// datasets it vouches for: a restore that brings back the data brings back the witness, so
/// the pair cannot disagree. The boot reconcile compares it against the configured keyspace
/// before processing removals, which stops a re-pointed config from being applied at restart
/// as the mass eviction the live reload refuses.
///
/// Equality is on the wire spelling: a trailing slash on `endpoint` or `prefix` is dropped by
/// the S3 client before any request, so two witnesses that differ only there name one
/// keyspace. [`S3Bucket::keyspace_witness`] constructs the canonical form; the comparison
/// normalises as well, because a witness on disk may still carry the slash and the boot gate
/// must not read a re-spelling as a re-pointed keyspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyspaceWitness {
    /// The S3 endpoint URL the channel polls.
    pub endpoint: String,
    /// The bucket name within that endpoint.
    pub bucket: String,
    /// The key prefix confining the channel (empty = the whole bucket).
    pub prefix: String,
}

impl KeyspaceWitness {
    /// The three parts as the S3 client addresses them — the identity `==` compares.
    fn wire_parts(&self) -> (&str, &str, &str) {
        (
            wire_endpoint(&self.endpoint),
            &self.bucket,
            wire_prefix(&self.prefix),
        )
    }
}

impl PartialEq for KeyspaceWitness {
    fn eq(&self, other: &Self) -> bool {
        self.wire_parts() == other.wire_parts()
    }
}

impl Eq for KeyspaceWitness {}

impl Default for S3Bucket {
    fn default() -> Self {
        Self {
            name: String::new(),
            endpoint: None,
            bucket: None,
            prefix: String::new(),
            region: None,
            path_style: false,
            allow_http: false,
            access_key_id: None,
            secret_access_key: None,
            marker_poll_interval: 30,
            full_poll_interval: 300,
            write_status: false,
            allowed_writer_fingerprints: Vec::new(),
        }
    }
}

impl std::fmt::Debug for S3Bucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Bucket")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("region", &self.region)
            .field("path_style", &self.path_style)
            .field("allow_http", &self.allow_http)
            .field("access_key_id", &self.access_key_id)
            .field(
                "secret_access_key",
                &redacted(self.secret_access_key.as_ref()),
            )
            .field("marker_poll_interval", &self.marker_poll_interval)
            .field("full_poll_interval", &self.full_poll_interval)
            .field("write_status", &self.write_status)
            .field(
                "allowed_writer_fingerprints",
                &self.allowed_writer_fingerprints,
            )
            .finish()
    }
}

/// The `[vault]` block — the Vault KV/Transit client config, gated by the
/// `vault` Cargo feature.
///
/// Named for the Vault HTTP API, not the vendor: HashiCorp Vault and OpenBao speak the
/// identical KV v2 + Transit API, so this one block points at either server unchanged. When
/// present, Vault is the source for every secret the service consumes (the crypt4gh
/// identity, the per-bucket S3 credentials), taking precedence over the inline `[keys]` /
/// `[[s3.buckets]]` values, which become the no-Vault fallback.
///
/// Auth is either a static `token` or `AppRole` (`role_id` + `secret_id`). The
/// bootstrap credential is supplied out-of-band (mounted Secret / env), never from
/// Vault: `token` may come from `VAULT_TOKEN` and `secret_id` from
/// `GDI_NODE__VAULT__SECRET_ID`.
#[expect(
    clippy::doc_markdown,
    reason = "docs use proper nouns (Vault, OpenBao, HashiCorp, HCP) as prose, not code"
)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VaultConfig {
    /// The Vault / OpenBao server base URL (e.g. `https://vault.example.org`).
    /// Required when `[vault]` is present (validated by the service preflight).
    pub address: String,
    /// Optional Vault namespace (HCP / Vault Enterprise; sent as the
    /// `X-Vault-Namespace` header). Omit for OpenBao / open-source Vault.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Static auth token, and the highest-precedence auth method: when set (non-empty) it
    /// wins over `role_id`/`secret_id` and over a bare `VAULT_TOKEN` env var. Only the
    /// figment overlay `GDI_NODE__VAULT__TOKEN` overrides this field; the conventional bare
    /// `VAULT_TOKEN` env var is the lowest-precedence fallback, consulted only when neither
    /// this token nor `role_id`/`secret_id` is set (see `resolve_auth`). Set this or
    /// `role_id`/`secret_id`, never both.
    // Secret: never serialized, so a config dump / echo / log line cannot leak it, mirroring
    // the tool side's `ProfileS3` credentials. Still deserializes from TOML / env. `[vault]`
    // uses figment's native overlay, not a serialize round-trip, so skipping it here (unlike
    // `S3Bucket.secret_access_key`) drops nothing on load.
    #[serde(skip_serializing)]
    pub token: Option<String>,
    /// Path to a file holding the Vault token, re-read when the file changes.
    ///
    /// This is the credential-free deployment shape: an external agent sidecar
    /// authenticates by whatever method the server supports (Kubernetes, JWT/OIDC, AWS IAM,
    /// TLS cert), renews continuously, and writes the current token here, typically onto an
    /// in-memory volume. The node then holds no static credential and implements none of
    /// those auth methods itself.
    ///
    /// Mutually exclusive with `token`: setting both is rejected by preflight rather than
    /// resolved by a silent precedence rule. Must be absolute — a relative path would
    /// resolve against the process working directory, which differs between a systemd unit
    /// and a container. The path itself is not secret and is serialized; its contents are,
    /// and are never logged or `Debug`-formatted.
    ///
    /// The agent owns renewal, so the node does not call `renew-self` for this token and
    /// instead re-reads the file when its mtime changes. A file that stops being refreshed
    /// is therefore invisible to `VaultRenewalFailing`, and the TTL gauge stays `0` so
    /// `VaultTokenLeaseTooShort` cannot fire either — watch
    /// `gdi_vault_token_file_age_seconds` / `VaultTokenFileStale` instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,
    /// `AppRole` role id (preferred for long-running / Kubernetes deployments).
    /// Paired with `secret_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_id: Option<String>,
    /// `AppRole` secret id. May instead come from `GDI_NODE__VAULT__SECRET_ID` (the
    /// out-of-band bootstrap credential). Paired with `role_id`.
    // Secret: never serialized (see `token`). Still deserializes from TOML /
    // `GDI_NODE__VAULT__SECRET_ID`.
    #[serde(skip_serializing)]
    pub secret_id: Option<String>,
    /// KV v2 mount path (default `secret`).
    pub kv_mount: String,
    /// KV v2 path holding the node's crypt4gh identity(ies). Required when
    /// `[vault]` is present (the identity source). See `kv_path` in the config
    /// example.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kv_path: Option<String>,
    /// KV v2 path holding the S3 credentials, keyed by each bucket's `name`. Omit
    /// when not using S3 or to keep inline `[[s3.buckets]]` creds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_path: Option<String>,
    /// Vault Transit mount for the at-rest master key (default `transit`). Only
    /// used when `transit_key` is set (PME).
    pub transit_mount: String,
    /// The Transit master-key name for at-rest PME. Its presence is the PME runtime switch;
    /// there is no separate flag. It additionally requires the `pme` Cargo feature (checked
    /// by the service's feature preflight). Omit to leave at-rest as volume-level only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transit_key: Option<String>,
    /// Connect timeout for the Vault HTTP client (seconds). Bounds how long a
    /// TCP/TLS connect to a dead / black-holed Vault endpoint may hang before
    /// failing as a transient error, instead of waiting out the OS default (minutes)
    /// while pinning a blocking-pool thread. Default 10; `0` disables (unbounded).
    pub connect_timeout_seconds: u64,
    /// Total per-request timeout for the Vault HTTP client (seconds). Bounds a
    /// slowloris / wedged Vault response so it surfaces as a bounded transient error
    /// rather than hanging a worker. Default 30; `0` disables (unbounded).
    pub request_timeout_seconds: u64,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            namespace: None,
            token: None,
            token_file: None,
            role_id: None,
            secret_id: None,
            kv_mount: "secret".to_owned(),
            kv_path: None,
            s3_path: None,
            transit_mount: "transit".to_owned(),
            transit_key: None,
            connect_timeout_seconds: 10,
            request_timeout_seconds: 30,
        }
    }
}

impl std::fmt::Debug for VaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultConfig")
            .field("address", &self.address)
            .field("namespace", &self.namespace)
            .field("token", &redacted(self.token.as_ref()))
            .field("token_file", &self.token_file)
            .field("role_id", &self.role_id)
            .field("secret_id", &redacted(self.secret_id.as_ref()))
            .field("kv_mount", &self.kv_mount)
            .field("kv_path", &self.kv_path)
            .field("s3_path", &self.s3_path)
            .field("transit_mount", &self.transit_mount)
            .field("transit_key", &self.transit_key)
            .field("connect_timeout_seconds", &self.connect_timeout_seconds)
            .field("request_timeout_seconds", &self.request_timeout_seconds)
            .finish()
    }
}

impl VaultConfig {
    /// The auth methods this config file supplies, named for an operator-facing message.
    ///
    /// "What counts as configured" is defined here alone, so the preflight exclusivity check
    /// and the runtime resolver cannot disagree, and a fourth method cannot be added without
    /// entering the count.
    ///
    /// `AppRole` counts when *either* half is present: a leftover `role_id` beside a new
    /// `token_file` is a half-finished migration worth rejecting, and the "needs both
    /// `role_id` and `secret_id`" check reports the incomplete pair on its own.
    ///
    /// Excludes the bare `VAULT_TOKEN` environment fallback: that is ambient process state,
    /// not something written here.
    #[must_use]
    pub fn configured_auth_methods(&self) -> Vec<&'static str> {
        let mut found = Vec::new();
        if self.token.as_deref().is_some_and(|t| !t.is_empty()) {
            found.push("vault.token");
        }
        if self.token_file.is_some() {
            found.push("vault.token_file");
        }
        if self.role_id.as_deref().is_some_and(|r| !r.is_empty())
            || self.secret_id.as_deref().is_some_and(|s| !s.is_empty())
        {
            found.push("vault.role_id/secret_id (AppRole)");
        }
        found
    }

    /// The configured KV v2 mount, defaulting to `secret` when unset/empty (so an
    /// explicit empty string in TOML still resolves to the default).
    #[must_use]
    pub fn kv_mount(&self) -> &str {
        if self.kv_mount.is_empty() {
            "secret"
        } else {
            &self.kv_mount
        }
    }

    /// The configured Transit mount, defaulting to `transit` when unset/empty.
    #[must_use]
    pub fn transit_mount(&self) -> &str {
        if self.transit_mount.is_empty() {
            "transit"
        } else {
            &self.transit_mount
        }
    }
}

/// The `[keys]` block — the node's crypt4gh identities, tried in order when
/// decrypting an inbound `.tar.c4gh`.
///
/// Vault is out of scope here (`[keys]` files only). With an empty list — the default — the
/// node is keyless: crypt4gh decryption and `/.well-known/c4gh-recipient` are disabled, and
/// only plaintext staging dirs ingest. The node's recipient, the public key published at the
/// well-known endpoint, is derived from the first identity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeysConfig {
    /// Paths to unencrypted crypt4gh secret-key files, tried in order. Relative
    /// paths are resolved by the caller against the config/working directory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identities: Vec<PathBuf>,
}

/// OTLP trace-export headers (e.g. an `Authorization` API key for a hosted collector). A
/// newtype over the header map whose `Debug` redacts every value at the type level, the same
/// "a secret never `Debug`s its value" contract the logging module relies on. Because the
/// type protects the secret, the derived `Debug` on the enclosing [`ServiceSection`], or a
/// stray `debug!(?config)`, can never print the header values; header names are not secret
/// and are shown, so the config stays diagnosable.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OtlpHeaders(pub BTreeMap<String, String>);

impl std::fmt::Debug for OtlpHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Names shown, every value redacted — the value never reaches the formatter.
        f.debug_map()
            .entries(self.0.keys().map(|k| (k.as_str(), "***")))
            .finish()
    }
}

/// The `[service]` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent operator toggles (strict_key_perms / expose_dataset_list / \
              trust_inbound_traceparent / …), not a state machine, and each one is a \
              `[service]` TOML key, so grouping them to satisfy the lint would rename \
              operator-facing config"
)]
pub struct ServiceSection {
    /// Address the public HTTP listener binds (`host:port`). Default `0.0.0.0:8080`.
    pub listen: String,
    /// Externally-reachable base URL; required. A trailing slash is stripped on
    /// load so generated URIs never contain a doubled `//`.
    pub base_url: String,
    /// Directory holding ingested `datasets/{id}/` dirs and `datasets/.status.json`.
    pub data_dir: PathBuf,
    /// Optional local drop directory (a "local bucket"); omit to disable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbox: Option<PathBuf>,
    /// The operator-override store root: node-local state for operator-authored
    /// dataset/channel suppressions and overlays (`suppressions/`, `overlays/` and
    /// `reingest/` subdirectories). Unset (the default) resolves to `<data_dir>/overrides/`;
    /// read the effective path through [`ServiceSection::override_dir_resolved`]. An empty
    /// store means no overrides are in force.
    ///
    /// Because the default lives inside `data_dir`, the store shares the fate of the data
    /// volume — but unlike everything else there it cannot be rebuilt by re-ingesting from
    /// the source bucket. Point this at separately-backed storage on any node that records
    /// overrides, and see `require_override_store` for the assertion that makes its loss
    /// loud. Moving this path discards the overrides at the old location, since an absent
    /// store reads as the empty set, so copy the directory across before changing it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_dir: Option<PathBuf>,
    /// Assert that the operator-override store must exist, and refuse to serve if it does
    /// not. Default `false`, where an absent store root reads as "no overrides" — correct
    /// for a node that has never suppressed or corrected anything, and indistinguishable
    /// from a store that has been destroyed.
    ///
    /// Set this on any node that *has* recorded an override. The config is mounted from
    /// outside the data volume, so it survives the incident that destroys the store, and it
    /// is the only thing on the node that can testify the store was supposed to be there.
    /// Without it, the recovery in `docs/operating.md` §17 (fresh volume, re-ingest from the
    /// bucket) silently re-serves every withheld dataset, because re-ingest restores each
    /// dataset to its source-resolved state — the state the operator overrode.
    ///
    /// The assertion demands an intact store — the root plus `suppressions/` and `overlays/`
    /// — and creates none of them: a check that materialises what it then tests would pass
    /// for an empty re-provisioned volume, the one incident this flag exists for. A node
    /// that has recorded any override already has the directories; one that sets this flag
    /// first needs a one-time `overrides init`.
    pub require_override_store: bool,
    /// Max packages ingested in parallel — the node-wide ingest ceiling, shared across all
    /// triggers and all `[[s3.buckets]]` providers, since one node fronts many providers
    /// through this single pool. Default `4`: high enough that a couple of slow packages
    /// cannot starve every other provider, bounded because each ingest is decrypt + validate
    /// + parquet heavy. Raise it only with the CPU and memory headroom to match.
    pub ingest_concurrency: usize,
    /// Per-job ingest timeout (seconds). Default `3600`. A single ingest that blocks longer
    /// than this (a hung Vault mint, a stuck fsync on a degraded volume, a pathological
    /// decode) frees its worker so the queue keeps draining; otherwise `ingest_concurrency`
    /// hung jobs wedge all ingest with no recovery short of a restart. `0` disables the
    /// timeout and restores that wedge risk.
    ///
    /// The blocking task cannot be cancelled, so a timed-out thread runs to completion in
    /// the background. If it does complete, the periodic full reload re-hydrates the dataset
    /// without a restart and its source drop is left in place rather than misreported as a
    /// rejected re-drop; only a genuinely hung one needs a restart (see
    /// `docs/operating.md`). Size this above the wall-clock of the largest legitimate
    /// ingest, so a merely slow job is not detached needlessly.
    pub ingest_timeout_seconds: u64,
    /// Period of the safety-net full reload and inbox rescan (seconds). Default `600`.
    pub rescan_interval_seconds: u64,
    /// Per-bucket hard timeout for the startup reconcile that gates readiness (seconds).
    /// Default `30`. Each configured `[[s3.buckets]]` bucket's initial listing and sidecar
    /// fetch runs concurrently under this bound; a bucket that exceeds it is logged, marked
    /// unhealthy and skipped, so one unreachable or slow provider bucket cannot block the
    /// node from binding. The bucket keeps retrying on its normal poll cadence afterwards.
    /// `0` is floored to 1 s.
    pub startup_reconcile_timeout_seconds: u64,
    /// Global request-body cap (bytes); oversized requests get 413. Default `262144`.
    pub max_request_body_bytes: usize,
    /// Per-request timeout (seconds). Default `30`; must not exceed
    /// `shutdown_drain_seconds`.
    pub request_timeout_seconds: u64,
    /// Graceful-shutdown drain budget for in-flight requests (seconds). Default `30`.
    pub shutdown_drain_seconds: u64,
    /// Global in-flight request cap; over-limit requests shed with 503. Default `64`.
    pub max_concurrent_requests: usize,
    /// Aggregate heap ceiling in bytes for a single `g_variants` query's retained scan rows,
    /// summed across every dataset the query fans out over. Default 2 GiB; must be at least
    /// 1.
    ///
    /// The per-dataset `max_query_rows` cap bounds one dataset's rows, but a query over N
    /// visible datasets retains all N row sets at once, and a row can weigh ~20 KB
    /// (10 000-base REF/ALT) rather than the ~100 B a row count assumes, so an
    /// unauthenticated wide query can drive the process to OOM. Once a query's accumulated
    /// rows exceed this it is rejected `400` (too broad), like the span cap. The default sits
    /// comfortably above a single legitimate dataset at its row cap with normal alleles, and
    /// low enough to stop the aggregate/long-allele blow-up. Tune it down for a stricter
    /// memory envelope.
    pub max_query_bytes: u64,
    /// Per-dataset row ceiling for a single `g_variants` scan. Default 10 000 000; must be
    /// at least 1, since `0` would reject every query.
    ///
    /// Where `max_query_bytes` bounds the aggregate heap a query retains across every dataset
    /// it fans out over, this bounds one dataset's contribution, and it fails closed *during*
    /// the scan (the budgeted read stops mid-file once the cumulative total would pass it)
    /// rather than after the rows are materialised. It is the cheaper of the two to trip and
    /// the one to lower on a memory-constrained node.
    ///
    /// Rows are `distinct loci × populations`, so the driver is the dataset's population
    /// count, not its size on disk: `[beacon]` permits up to 512 populations, and a 14 MiB
    /// dataset at 101 populations carries ~5.2M rows. Sizing this from the store's disk
    /// footprint under-provisions by orders of magnitude — see `docs/deployment.md`
    /// §"Resource baseline".
    pub max_query_rows: usize,
    /// Process-wide heap ceiling in bytes for retained scan rows, summed across every
    /// `g_variants` query in flight at once. Default 8 GiB, four times the default
    /// `max_query_bytes`; must be at least `max_query_bytes`, since a single request that
    /// cannot fit in the global budget could never run.
    ///
    /// `max_query_bytes` is a per-request ceiling, so without this bound the exposure is that
    /// ceiling multiplied by `max_concurrent_requests`: each concurrent request carries its
    /// own full allowance. A query that would push the process past this is shed with `503`
    /// (a capacity condition, like the scan-pool shed) rather than `400` — the request is not
    /// too broad, the node is momentarily too busy to serve it. The default is a backstop set
    /// generously so it does not throttle legitimate concurrent traffic; lower it to hold a
    /// tighter memory envelope.
    pub max_total_query_bytes: u64,
    /// How many per-dataset Beacon scans one `g_variants` query may run at once.
    ///
    /// `None`, the default, means "follow `ingest_concurrency`". Set it to decouple the two,
    /// so that tuning ingest throughput does not also widen public query concurrency — the
    /// axis that multiplies query memory, since each concurrent scan retains its own rows
    /// (see `max_total_query_bytes`).
    ///
    /// Must be at least 1 when set. Both scan paths (`record` and the `boolean`/`count` fold)
    /// read it through `ServiceSection::query_concurrency()`, so they cannot diverge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_concurrency: Option<usize>,
    /// Bound (seconds) on how long a channel may keep serving at its last-known visibility
    /// after its bucket goes unreachable. A reached-then-dark S3 bucket fails reconcile open,
    /// to avoid dropping a live provider on a transient blip, so a source-side
    /// retraction issued during the outage is not observed and the dataset keeps being
    /// served — served-and-stale. A channel whose last successful reconcile is older than
    /// the bound has its datasets forced `Hidden` at serve time.
    ///
    /// Default `86_400` (24 h). The trade is asymmetric: disabled, the node serves a
    /// possibly-retracted dataset for an unbounded time and reports nothing; bounded, it
    /// costs a visible, self-correcting withdrawal that an operator already has
    /// `S3PollerWedged` / `HealthNotReady` signals for. Set `0` to disable where availability
    /// during a long provider outage outweighs retraction freshness.
    ///
    /// Enabling it is cheap: both gate paths short-circuit on
    /// `Readiness::any_channel_stale`, which reads the per-channel reconcile map, so the
    /// steady state never touches the status index. Does not affect the local `inbox` channel,
    /// which does no reconcile and is not a dark-bucket concern.
    pub max_visibility_staleness_seconds: u64,
    /// Browser Origins allowed to call the public data plane (CORS). Empty, the default,
    /// serves the wildcard `Access-Control-Allow-Origin: *` this all-public aggregate beacon
    /// ships with. A non-empty list restricts the public plane to those exact origins: each
    /// entry must be a bare HTTP(S) origin (`scheme://host[:port]`, no
    /// path/query/fragment/credentials, no trailing slash), because the CORS layer matches it
    /// byte-for-byte against the request `Origin` header, which a browser sends in that
    /// canonical form. The literal `"*"` is accepted as an explicit wildcard, but only on its
    /// own — mixing it with specific origins is contradictory and rejected by preflight.
    ///
    /// This is not an access control. CORS only constrains what browser JavaScript on another
    /// origin may read; it does nothing against `curl`, a server-side fetch or a proxy. On an
    /// internet-public, unauthenticated node it buys no confidentiality, since anyone can
    /// fetch the same data directly, and is hygiene only. It earns its keep on a node whose
    /// data plane is not internet-reachable (intranet or VPN-only): there the wildcard lets
    /// any site a user inside that network visits use their browser as a read-proxy for the
    /// node, and an allow-list closes that. The boundary for a non-public node remains
    /// network policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cors_allowed_origins: Vec<String>,
    /// Reject a single parquet data file larger than this (bytes). Default 1 GiB.
    pub max_parquet_file_bytes: u64,
    /// Reject a parquet file whose decompressed working set exceeds this (bytes). Default
    /// 4 GiB.
    pub max_parquet_decompressed_bytes: u64,
    /// Cap the decompressed working set per row group (bytes). Default 256 MiB.
    pub max_parquet_row_group_bytes: u64,
    /// Reject an encrypted `.tar.c4gh` package whose decrypted `.tar` exceeds this (bytes).
    /// Default 16 GiB, well above a realistic aggregated dataset. Enforced while streaming
    /// the decrypt to disk, so an oversized package is rejected before extraction, bounding
    /// the bytes written to the data volume rather than only the post-extraction tree. Also
    /// caps the summed regular-file bytes of the extracted/staging tree
    /// (`ExtractBounds::max_total_bytes`). The over-cap failure is a permanent
    /// `unsafe-archive` error and is not retried.
    pub max_package_bytes: u64,
    /// Reject a package / staging tree with more than this many members (files +
    /// directories) — `ExtractBounds::max_members`. Default 100 000.
    pub max_package_members: usize,
    /// Collect `inbox/.rejected/{id}/` entries older than this (hours). Default `168`
    /// (7 days). `0` disables age-based eviction and keeps the forensic quarantine forever,
    /// parallel to `rejected_max_count`'s `0`; the count cap still bounds total quarantine
    /// size, and preflight rejects setting both to `0`.
    ///
    /// Also bounds abandoned inbox staging artifacts (`*.partial`, `.{id}.partial`) left by
    /// an interrupted `deploy` or hand-drop. The scanner skips those, correctly, since they
    /// may still be being written, so nothing else reclaims them. One knob rather than a
    /// second retention policy: both answer "how long is inbox debris kept?".
    pub rejected_retention_hours: u64,
    /// Cap the number of quarantined `inbox/.rejected/{id}/` entries: when the count exceeds
    /// this, the oldest entries are evicted down to the cap on the next collection. Default
    /// `1000`; `0` disables the cap. Age-based retention alone is not a bound, because a
    /// producer dropping many distinct bad packages within the retention window can fill the
    /// shared volume (per-id quarantine self-bounds only one id).
    pub rejected_max_count: usize,
    /// Unix only. Refuse to start on a group/other-readable (`mode & 0o077 != 0`) crypt4gh
    /// identity key file. Default `true` (fail closed): the node identity is the one
    /// irreplaceable secret, decrypting every inbound `.tar.c4gh` and all PME-at-rest
    /// parquet, so a world- or group-readable key file must not boot silently. Set `false`
    /// only for a knowingly relaxed development setup.
    pub strict_key_perms: bool,
    /// The separate management-plane listener (`host:port`): liveness/readiness, the
    /// dataset-state oracle, and `/metrics`. Kept off the public `listen` and the
    /// public Ingress so misconfiguring the Ingress can only ever expose the public data
    /// plane, never the hidden-dataset oracle.
    ///
    /// Default `127.0.0.1:9090` (loopback), because this plane carries the oracle and
    /// metrics. Local and bare-metal deployments probe over localhost and need no change. A
    /// containerized deployment whose probe or scrape reaches the pod over its IP (Docker
    /// `-p`, a kubelet liveness probe) must set `"0.0.0.0:9090"` explicitly, gated by a
    /// `NetworkPolicy`; forgetting that fails loudly — the probe cannot reach the plane, so
    /// the pod never goes Ready — rather than exposing it silently. The bind is a hard
    /// startup requirement: the node exits if it cannot bind, and preflight refuses to start
    /// if the value is empty or equals `listen`.
    pub management_addr: String,
    /// Serve `GET /datasets` on the management plane — the whole inventory the `dataset
    /// list` CLI prints, over HTTP. Default `false`.
    ///
    /// Opt-in because it changes what the management plane's dataset oracle is. With it off,
    /// `GET /datasets/{id}/state` answers a question the caller already had to know to ask;
    /// with it on, one request enumerates every dataset the node holds, including the hidden
    /// ones — the point for an operator, and the risk for everyone else. Off, the route is a
    /// plain `404`, so a caller cannot probe for the flag itself.
    ///
    /// It is not a substitute for keeping the plane closed: the listener is loopback by
    /// default and, in a cluster, reachable only through a `NetworkPolicy`. Turn it on where
    /// an operator, a dashboard or a back-office consumes it.
    pub expose_dataset_list: bool,
    /// Optional OTLP/HTTP endpoint for exporting `tracing` spans as OpenTelemetry traces
    /// (e.g. `http://collector:4318`). Unset by default, which turns trace export off.
    ///
    /// Acted upon only when the binary is built with the `otel` feature; a build without it
    /// parses but ignores this field, and preflight warns. The exported spans are
    /// content-free by construction: the `audit` tracing target, the one site that can carry
    /// beacon query detail, is excluded from trace export, so a trace backend never becomes a
    /// "who queried what" store (see `docs/operating.md`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otlp_endpoint: Option<String>,
    /// Optional headers added to every OTLP export request, traces and the metrics push
    /// alike — for example an auth token for a hosted collector (`[service.otlp_headers]`
    /// with `Authorization = "ApiKey <base64>"`). Unset by default. The value is a secret, so
    /// prefer the `GDI_NODE__SERVICE__OTLP_HEADERS__<NAME>` env overlay. Acted upon only with
    /// the `otel` feature. An `https://` endpoint is verified against the OS CA bundle in
    /// every build carrying the `tls` group (`full`), so an authenticated TLS intake needs no
    /// fronting collector; over `http://` the header travels in cleartext, and preflight
    /// warns in production.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otlp_headers: Option<OtlpHeaders>,
    /// Optional OTLP metrics push. Unset by default, which turns the push off. When set,
    /// every series `/metrics` serves is also exported as OpenTelemetry metrics to
    /// [`otlp_endpoint`](Self::otlp_endpoint) (`/v1/metrics`) once per this many seconds,
    /// for a store with no Prometheus scraper of its own. `/metrics` keeps serving
    /// regardless, and the series names travel verbatim (`gdi_*_total`, histograms with
    /// their buckets), so the same names the alert rules use appear in the store. Acts only
    /// in an `otel` build with `otlp_endpoint` set; preflight rejects `0`, a typo for "off"
    /// that would otherwise mean "export continuously".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otlp_metrics_interval_seconds: Option<u64>,
    /// Optional trace sampling: the fraction of new traces this node exports, `0.0`–`1.0`.
    /// Unset means `1.0`, every request. Sampling is parent-based, so a request arriving with
    /// a trusted `traceparent` follows its parent's decision and a sampled upstream trace is
    /// never cut off at this node. Only the exported spans are sampled: the log lines of an
    /// unsampled request still carry their trace id. Acts only in an `otel` build with
    /// `otlp_endpoint` set; preflight rejects a value outside `0.0..=1.0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otlp_trace_sample_ratio: Option<f64>,
    /// Honour a `traceparent` arriving as an HTTP header, adopting it as the request span's
    /// parent so this node's spans nest under an upstream trace. Default `false`.
    ///
    /// An inbound header is caller-controlled, so it is ignored unless the operator asserts
    /// that the node sits behind a trusted ingress (a reverse proxy or gateway) that sets it
    /// and strips any client-supplied one. It covers both listeners, and the public one is
    /// internet-facing: turning it on lets any client choose the trace ids the node's spans
    /// hang under. A malformed header is ignored and the server-side root stands. Meaningful
    /// only with the `otel` feature and `otlp_endpoint` set; a non-`otel` build parses but
    /// ignores it.
    #[serde(default)]
    pub trust_inbound_traceparent: bool,
    /// Honour a `traceparent` carried in an S3 handoff sidecar (`{id}.state.json`),
    /// parenting that package's `ingest_job` span under the orchestrator's trace. Default
    /// `false`.
    ///
    /// Separate from [`trust_inbound_traceparent`](Self::trust_inbound_traceparent) because
    /// the two are different trust questions with the same name: reaching this one means
    /// holding write credentials for a configured bucket, the same authority that decides
    /// what the node ingests at all, whereas the HTTP header is anyone who can reach the
    /// port. The two are independent, so a node may trust the sidecar while continuing to
    /// ignore every inbound header, which is the recommended posture. Same
    /// `otel`/`otlp_endpoint` caveat as its sibling.
    #[serde(default)]
    pub trust_sidecar_traceparent: bool,
}

impl Default for ServiceSection {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".to_owned(),
            base_url: String::new(),
            data_dir: PathBuf::new(),
            inbox: None,
            override_dir: None,
            require_override_store: false,
            ingest_concurrency: 4,
            ingest_timeout_seconds: 3600,
            rescan_interval_seconds: 600,
            startup_reconcile_timeout_seconds: 30,
            max_request_body_bytes: 262_144,
            request_timeout_seconds: 30,
            shutdown_drain_seconds: 30,
            max_concurrent_requests: 64,
            max_query_bytes: 2 * 1024 * 1024 * 1024,
            max_query_rows: crate::validate_parquet::ParquetCaps::default().max_query_rows,
            max_total_query_bytes: 8 * 1024 * 1024 * 1024,
            query_concurrency: None,
            max_visibility_staleness_seconds: 86_400,
            // Empty = the wildcard `*` CORS the public aggregate beacon ships with.
            cors_allowed_origins: Vec::new(),
            max_parquet_file_bytes: 1_073_741_824,
            max_parquet_decompressed_bytes: 4_294_967_296,
            max_parquet_row_group_bytes: 268_435_456,
            max_package_bytes: 16 * 1024 * 1024 * 1024,
            max_package_members: 100_000,
            rejected_retention_hours: 168,
            rejected_max_count: 1_000,
            strict_key_perms: true,
            // Loopback: the management plane carries the hidden-dataset oracle and metrics,
            // so it must not bind every interface unless the operator opts in. See the field
            // doc for the containerized case.
            management_addr: "127.0.0.1:9090".to_owned(),
            expose_dataset_list: false,
            otlp_endpoint: None,
            otlp_headers: None,
            otlp_metrics_interval_seconds: None,
            otlp_trace_sample_ratio: None,
            trust_inbound_traceparent: false,
            trust_sidecar_traceparent: false,
        }
    }
}

impl ServiceSection {
    /// The Parquet resource caps the service enforces on ingested and queried data, derived
    /// from the operator-tunable `[service]` caps. The non-configurable fields
    /// (`max_ref_len`, `max_alt_len`, `max_distinct_keys_per_pos`, `max_pos_key_bytes`,
    /// `max_population_len`, `max_files_per_group`) keep their `ParquetCaps::default()`
    /// values, the same frozen values the `gdi-dataset-tool` producer validates against, so
    /// producer and consumer agree by construction (pinned by
    /// `service_default_caps_match_tool_default`).
    ///
    /// `max_query_rows` is not one of them: it bounds a query at serve time, the producer
    /// never reads it, and an operator needs it as the per-dataset lever on query memory.
    /// It defaults to the same value, so the producer/consumer guard still holds.
    #[must_use]
    pub fn parquet_caps(&self) -> crate::validate_parquet::ParquetCaps {
        crate::validate_parquet::ParquetCaps {
            max_parquet_file_bytes: self.max_parquet_file_bytes,
            max_parquet_decompressed_bytes: self.max_parquet_decompressed_bytes,
            max_parquet_row_group_bytes: self.max_parquet_row_group_bytes,
            max_query_rows: self.max_query_rows,
            ..crate::validate_parquet::ParquetCaps::default()
        }
    }

    /// The per-query Beacon scan fan-out cap: `query_concurrency` when set, else
    /// `ingest_concurrency`.
    ///
    /// The one resolution point, read by both scan paths, so the record path and the
    /// aggregate `boolean`/`count` fold cannot end up with different caps.
    #[must_use]
    pub fn query_concurrency(&self) -> usize {
        self.query_concurrency.unwrap_or(self.ingest_concurrency)
    }

    /// The operator-override root: the configured `override_dir`, else
    /// `<data_dir>/overrides/`.
    ///
    /// An empty directory means "nothing suppressed", so no separate on/off flag is needed:
    /// the feature is inactive exactly when the resolved directory holds no override files.
    #[must_use]
    pub fn override_dir_resolved(&self) -> PathBuf {
        self.override_dir
            .clone()
            .unwrap_or_else(|| self.data_dir.join("overrides"))
    }
}

/// The `[beacon]` block — static values for the informational endpoints plus the
/// query knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BeaconConfig {
    /// Aggregated mount path (`g_variants`, datasets). Default `/aggregated/beacon/v2`.
    pub aggregated_base_path: String,
    /// Sensitive mount path (individuals placeholder). Default `/sensitive/beacon/v2`.
    pub sensitive_base_path: String,
    /// Beacon id (reverse-DNS).
    pub id: String,
    /// Human-readable beacon name.
    pub name: String,
    /// GA4GH Beacon schema version served. Pinned to
    /// [`SUPPORTED_BEACON_API_VERSION`]; preflight rejects any other value.
    pub api_version: String,
    /// Deployment environment (`dev` | `test` | `staging` | `prod`). Default `prod`.
    pub environment: String,
    /// Optional documentation URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    /// Reject range/bracket queries wider than this (bp). Default 10 000 000; `0` is
    /// unlimited.
    pub max_query_span_bp: u64,
    /// Default page size applied when a request omits it. Default `10`, and per dataset —
    /// see [`Self::max_page_limit`].
    pub default_page_limit: u64,
    /// Hard cap on `pagination.limit`, applied per dataset. Default `1000`.
    ///
    /// This is not a bound on response size. Each selected dataset materialises its own `resultSet`
    /// with its own `[skip, skip+limit)` window and the response concatenates them, so a query
    /// matching N visible datasets can return up to `N × max_page_limit` entries while
    /// `meta.receivedRequestSummary.pagination.limit` echoes this value. Adding a dataset
    /// therefore raises the maximum page with no config change. Pinned by
    /// `crates/beacon/tests/it/assemble.rs::pagination_limit_is_per_dataset_not_global`; see
    /// `docs/api.md` for the consumer-facing statement.
    pub max_page_limit: u64,
    /// Aggregated-path small-count suppression floor. Default `0`, which is off. Counts
    /// alleles, not individuals (a homozygote contributes 2 to `AC`), so individual-level
    /// anonymity is about `floor/2`; use about `2k` for k distinct people.
    ///
    /// This is the node's serve-time floor, applied to every beacon response. It is a
    /// different knob from the provider's build-time floor
    /// ([`PackageConfig::min_allele_count`], `config.minAlleleCount` in `package.yaml`),
    /// which drops rows once at `gdi-dataset-tool build`, so those rows never reach the node.
    /// The two compose: the effective floor is `max(build-time, serve-time)`. A build-time
    /// floor cannot be lowered later without rebuilding the package; this one can be retuned
    /// by restarting the node. The floor in force is reported per dataset as
    /// `gdiDatasetInfo.minAlleleCount`.
    ///
    /// [`PackageConfig::min_allele_count`]: crate::model::PackageConfig::min_allele_count
    pub min_allele_count: u32,
    /// Optional free-text description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional beacon version string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Optional alternative URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternative_url: Option<String>,
    /// Optional creation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Optional last-update timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// `[beacon.organization]` nested table.
    pub organization: BeaconOrganization,
    /// `[beacon.configuration]` nested table.
    pub configuration: BeaconConfiguration,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            aggregated_base_path: "/aggregated/beacon/v2".to_owned(),
            sensitive_base_path: "/sensitive/beacon/v2".to_owned(),
            id: String::new(),
            name: String::new(),
            api_version: SUPPORTED_BEACON_API_VERSION.to_owned(),
            // The GA4GH `beaconInfoResults` schema makes `environment` a required,
            // closed enum (`prod|test|dev|staging`); default to a conformant value so a
            // node booted without an explicit `[beacon].environment` still serves a
            // schema-valid `/info` (matching `production_status`'s `PROD` default).
            environment: "prod".to_owned(),
            documentation_url: None,
            max_query_span_bp: 10_000_000,
            default_page_limit: 10,
            // See `BeaconParams::default` for why this is 1000 rather than 100, and
            // `docs/deployment.md` "Resource baseline" for what a 1000-row page costs.
            max_page_limit: 1000,
            min_allele_count: 0,
            description: None,
            version: None,
            alternative_url: None,
            created_at: None,
            updated_at: None,
            organization: BeaconOrganization::default(),
            configuration: BeaconConfiguration::default(),
        }
    }
}

/// The `[beacon.organization]` nested table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BeaconOrganization {
    /// Organization id (reverse-DNS).
    pub id: String,
    /// Organization name.
    pub name: String,
    /// Optional welcome URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome_url: Option<String>,
    /// Optional contact URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_url: Option<String>,
    /// Optional free-text description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional logo URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
}

/// The `[beacon.configuration]` nested table.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BeaconConfiguration {
    /// Default granularity (`boolean` | `count` | `record`). Default `record`.
    pub default_granularity: String,
    /// Production status (`DEV` | `TEST` | `PROD`). Default `PROD`. Advertised in `/info`,
    /// and it also gates the production Vault-https requirement: `PROD` enforces it even
    /// when `beacon.environment` is not `prod` (see `preflight_vault`).
    pub production_status: String,
    /// Security level for this node, which serves only public aggregated data. Default
    /// `PUBLIC`.
    pub security_level: String,
}

impl Default for BeaconConfiguration {
    fn default() -> Self {
        Self {
            default_granularity: "record".to_owned(),
            production_status: "PROD".to_owned(),
            security_level: "PUBLIC".to_owned(),
        }
    }
}

/// The `[fairdp]` block — the FAIR Data Point node identity: the invariant fields the
/// FDP-root and Catalog records carry. Those records are not datasets; datasets carry their
/// own license and applicableLegislation from `package.yaml`. Optional on [`ServiceConfig`],
/// since FDP is not required (beacon is). When present, [`ServiceConfig::preflight`]
/// enforces the mandatory publisher/HDAB contact points and the theme/theme-taxonomy
/// in-scheme rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FairdpConfig {
    /// FDP-root `dct:title` (required when `[fairdp]` is present).
    pub title: String,
    /// Optional FDP-root `dct:description`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// FDP-root `fdp-o:metadataIssued` (xsd:dateTime). `metadataModified` is
    /// data-derived at render time, falling back to this when nothing changed.
    pub issued: String,
    /// FDP-root + Catalog record license IRI (node identity; mandatory on both
    /// records). Datasets set their own license in `package.yaml`.
    pub license: String,
    /// `dct:language` for the FDP root, every catalog and every dataset: one node-level
    /// value, with no per-dataset override, because the node publishes in one language.
    ///
    /// An EU authority `language/…` IRI. Defaults to [`DEFAULT_FAIRDP_LANGUAGE`] (English).
    /// A harvester's DCAT profile reads it into the harvested dataset's `language` field, so
    /// an omitted value shows there as empty.
    pub language: String,
    /// Node-wide dataset/catalog theme concept IRIs. Each dataset record carries
    /// these directly as `dcat:theme`; the Catalog's `dcat:themeTaxonomy` is
    /// derived from them (their shared SKOS scheme).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub theme: Vec<String>,
    /// Optional override for the SKOS `ConceptScheme` of `theme` — only for a
    /// vocabulary whose scheme is not the concept's parent path. When set, every
    /// `theme` must be in-scheme (validated at preflight). Omit to derive it from
    /// `theme` (the concept IRI minus its final path segment).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme_taxonomy: Option<String>,
    /// Catalog record `dcatap:applicableLegislation` IRIs (node-level, no
    /// per-catalog override; datasets carry their own in `package.yaml`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applicable_legislation: Vec<String>,
    /// `[fairdp.publisher]` — `dct:publisher` (the node organisation; exactly one).
    pub publisher: FairdpPublisher,
    /// `[fairdp.hdab]` — `healthdcatap:hdab` (Member-State Health Data Access Body).
    pub hdab: FairdpHdab,
}

/// Every field is empty except `language`, which carries [`DEFAULT_FAIRDP_LANGUAGE`].
///
/// Hand-written rather than derived because of that one field: the container-level
/// `#[serde(default)]` fills each absent key from this value, so a `[fairdp]` block that
/// omits `language` gets the English IRI while every other field stays the empty string
/// preflight rejects. The empties are deliberate — the rest of this block is required
/// deployment metadata, not defaulted knobs.
impl Default for FairdpConfig {
    fn default() -> Self {
        Self {
            title: String::new(),
            description: None,
            issued: String::new(),
            license: String::new(),
            language: DEFAULT_FAIRDP_LANGUAGE.to_owned(),
            theme: Vec::new(),
            theme_taxonomy: None,
            applicable_legislation: Vec::new(),
            publisher: FairdpPublisher::default(),
            hdab: FairdpHdab::default(),
        }
    }
}

impl FairdpConfig {
    /// The Catalog record's `dcat:themeTaxonomy` SKOS `ConceptScheme` IRI.
    ///
    /// Returns the explicit `theme_taxonomy` override when set, else derives it
    /// from the first configured `theme` concept IRI (its parent path — the IRI
    /// minus its final `/`-segment). Returns [`None`] only when no themes are
    /// configured and no override is set. The themes are validated to share one
    /// derivable scheme at preflight (`ServiceConfig::check_theme_scheme`), so
    /// deriving from the first theme is sufficient and matches that scheme.
    #[must_use]
    pub fn theme_taxonomy_iri(&self) -> Option<String> {
        if let Some(taxonomy) = &self.theme_taxonomy {
            return Some(taxonomy.clone());
        }
        derived_theme_scheme(self.theme.first()?).map(ToOwned::to_owned)
    }
}

/// The `[fairdp.publisher]` nested table — the node organisation (`foaf:Agent` /
/// `foaf:Organization`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FairdpPublisher {
    /// `foaf:name` (required).
    pub name: String,
    /// `foaf:homepage` (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// `foaf:mbox` (optional; the Organization's own address — distinct from the
    /// contact-point vCard below).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mbox: Option<String>,
    /// `[fairdp.publisher.contact_point]` — required (the gdi-metadata submission
    /// model makes a contact point mandatory, card. 1, on the publisher agent).
    pub contact_point: ContactPointCfg,
}

/// The `[fairdp.hdab]` nested table — the Member-State Health Data Access Body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FairdpHdab {
    /// HDAB name (required).
    pub name: String,
    /// `[fairdp.hdab.contact_point]` — required (mandatory, card. 1, on the HDAB
    /// agent in the gdi-metadata submission model).
    pub contact_point: ContactPointCfg,
}

/// A vCard contact point (`[fairdp.publisher.contact_point]` /
/// `[fairdp.hdab.contact_point]`). `fn` + `has_email` are required; preflight
/// rejects an incomplete one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContactPointCfg {
    /// `vcard:fn` (required). The TOML/JSON key is `fn` (a Rust keyword, so the
    /// field is `fn_` with a serde rename).
    #[serde(rename = "fn")]
    pub fn_: String,
    /// `vcard:hasEmail` (required; `^mailto:.+@.+\..+$`).
    pub has_email: String,
    /// `vcard:hasURL` (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_url: Option<String>,
}

impl ServiceConfig {
    /// Resolve the config path, layer the TOML file under the `GDI_NODE__*` env
    /// overlay, and deserialize into a [`ServiceConfig`].
    ///
    /// Path precedence (highest first): the `cli_config` flag, the `GDI_CONFIG`
    /// env var, then the default `/etc/gdi-node-standalone/node.toml`. The chosen file
    /// is layered file < env (`GDI_NODE__SECTION__KEY`, double-underscore separator).
    /// A missing file at the default path is treated as empty (env-only), matching
    /// figment's `Toml::file` behaviour; a missing explicit path (`--config` /
    /// `$GDI_CONFIG`) is a hard error (see below).
    ///
    /// This does not run [`ServiceConfig::preflight`]; callers run it before binding the
    /// listener.
    ///
    /// # Errors
    ///
    /// Returns a boxed [`figment::Error`] if an explicit config path does not
    /// exist, if the TOML is malformed, or if the merged data does not deserialize
    /// into [`ServiceConfig`]. The error is boxed because `figment::Error` is large.
    pub fn load(cli_config: Option<&Path>) -> Result<Self, Box<figment::Error>> {
        let path = Self::resolve_path(cli_config);
        // An explicit config path (`--config` flag or `$GDI_CONFIG`) that does not exist is
        // a common deploy mistake: a config that did not mount, or a mistyped path. Fail
        // hard, naming the path, rather than silently loading an empty env-only config and
        // dying later with the pathless `base_url is required`. The default path stays
        // lenient, since an env-only run there is legitimate. An empty `$GDI_CONFIG` (a
        // common container default) means "unset", not an explicit path, so it falls through
        // to the lenient default path.
        let explicit =
            cli_config.is_some() || std::env::var_os("GDI_CONFIG").is_some_and(|v| !v.is_empty());
        if explicit && !path.exists() {
            return Err(Box::new(figment::Error::from(format!(
                "config file not found: {} (point --config / $GDI_CONFIG at an existing file, or \
                 unset it to use the default {DEFAULT_CONFIG_PATH})",
                path.display()
            ))));
        }
        Self::from_figment(Figment::new().merge(Toml::file(&path))).map_err(|e| {
            // Pointed at the provider tool's config? Say so, rather than leaving the
            // operator to decode a stray-key error from a disjoint schema.
            super::cross_config_hint(&path, super::ConfigKind::Service)
                .map_or(e, |hint| Box::new(figment::Error::from(hint)))
        })
    }

    /// Resolve the config-file path used by [`ServiceConfig::load`], applying the
    /// same precedence (highest first): the `cli_config` flag, the `GDI_CONFIG` env
    /// var, then the default `/etc/gdi-node-standalone/node.toml`.
    ///
    /// Exposed so the boot path can report the *resolved* path (in the startup log
    /// block and the `check-config` summary) without re-deriving the precedence.
    #[must_use]
    pub fn resolve_path(cli_config: Option<&Path>) -> PathBuf {
        cli_config.map_or_else(
            || {
                std::env::var_os("GDI_CONFIG")
                    .map_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH), PathBuf::from)
            },
            Path::to_path_buf,
        )
    }

    /// Build a [`ServiceConfig`] from an in-memory TOML string (no file on disk).
    ///
    /// Test/embedding helper so callers do not need a file on disk. The `GDI_NODE__`
    /// environment overlay is still applied, with the same precedence as
    /// [`ServiceConfig::load`] (env wins over the string); a misspelled `GDI_NODE__*`
    /// overlay key is a hard load error (the same `deny_unknown_fields` contract as
    /// the TOML file), never silently dropped. The trailing slash on `base_url` is
    /// stripped, exactly as in `load`.
    ///
    /// # Errors
    ///
    /// Returns a boxed [`figment::Error`] if the string is not valid TOML or does
    /// not deserialize into [`ServiceConfig`].
    pub fn from_toml_str(toml: &str) -> Result<Self, Box<figment::Error>> {
        Self::from_figment(Figment::new().merge(Toml::string(toml)))
    }

    /// Extract from a figment, applying the env overlay and load-time
    /// normalization (`base_url` trailing-slash strip).
    fn from_figment(fig: Figment) -> Result<Self, Box<figment::Error>> {
        // figment splits `GDI_NODE__S3__BUCKETS__0__SECRET_ACCESS_KEY` into a numeric-keyed
        // dict (`s3.buckets.0.secret_access_key`) that it cannot fold into the
        // `Vec<S3Bucket>` field, and even coalesced to an array it would replace the
        // TOML-defined buckets wholesale (figment merges dicts by key, but arrays are
        // winner-takes-all). So the per-bucket env overlay is pulled out of the generic
        // overlay here and index-merged onto the extracted buckets by
        // `apply_s3_bucket_env_overrides`, which preserves the documented per-index override
        // and fails loudly on a typo instead of silently dropping it. `.filter` runs before
        // `.split`, so it sees the raw `s3__buckets__…` key: `.split("__")` is a `map` that
        // has already rewritten `__` to `.` by the time a later filter would run.
        let env = Env::prefixed("GDI_NODE__")
            .filter(|k| !k.starts_with("s3__buckets__"))
            .split("__");
        let mut cfg: Self = fig.merge(env).extract().map_err(Box::new)?;
        Self::apply_s3_bucket_env_overrides(&mut cfg.s3)?;
        while cfg.service.base_url.ends_with('/') {
            cfg.service.base_url.pop();
        }
        // Canonicalize `[fairdp].issued` into the xsd:dateTime lexical space. Preflight
        // validates it with a lenient RFC-3339 parser (which accepts a space separator and a
        // lowercase `t`/`z`, forms outside xsd:dateTime), yet `issued` is emitted verbatim as
        // a typed `^^xsd:dateTime` literal on the FDP-root/Catalog
        // `metadataIssued`/`metadataModified`, and as the `dct:issued`/`dct:modified`
        // fallback. Re-serialize any parseable value to canonical form here so a strict SHACL
        // harvester never silently drops the node's records over an ill-typed literal; an
        // unparseable value is left untouched for `preflight_fairdp` to reject with a clear
        // error.
        if let Some(fairdp) = &mut cfg.fairdp
            && let Some(canonical) = crate::datetime::to_xsd_datetime(&fairdp.issued)
        {
            fairdp.issued = canonical;
        }
        Ok(cfg)
    }

    /// Apply the `GDI_NODE__S3__BUCKETS__<i>__<FIELD>` environment overrides onto the S3
    /// buckets, by index (the sub-overlay excluded from the generic env merge in
    /// [`Self::from_figment`], because figment cannot fold a numeric-keyed env dict
    /// into a `Vec`).
    ///
    /// An override for an existing bucket index field-patches that bucket (the
    /// documented "inject the secret via env without editing the TOML" path); an
    /// index one past the end appends a new bucket built from its fields (the
    /// env-only path, materializing `[s3]` if absent). A gap (an index beyond the
    /// next free slot) or an unknown field name is a hard error, so a mis-indexed or
    /// misspelled override fails loudly rather than being silently dropped.
    ///
    /// # Errors
    ///
    /// Returns a boxed [`figment::Error`] on a malformed key, an out-of-range index,
    /// an unknown field, or a value that does not parse to the field's type.
    fn apply_s3_bucket_env_overrides(s3: &mut Option<S3Config>) -> Result<(), Box<figment::Error>> {
        const PREFIX: &str = "GDI_NODE__S3__BUCKETS__";
        // Group overrides by index in ascending order (env iteration order is
        // unspecified, and appends must be processed lowest-index first).
        let mut overrides: BTreeMap<usize, Vec<(String, String)>> = BTreeMap::new();
        // Iterate `vars_os`, not `vars`, so an unrelated non-UTF-8 env var anywhere in
        // the process cannot panic config load or node startup.
        for (key, value) in std::env::vars_os() {
            let Some(key) = key.to_str() else {
                // A non-UTF-8 key can never match the ASCII prefix; skip it.
                continue;
            };
            // Match the prefix case-insensitively, mirroring figment's own case-insensitive
            // env handling, so a lower- or mixed-case override key is not silently dropped
            // from this merge path.
            let upper = key.to_ascii_uppercase();
            let Some(rest) = upper.strip_prefix(PREFIX) else {
                continue;
            };
            let Some(value) = value.to_str() else {
                return Err(Self::s3_env_err(format!(
                    "S3 bucket env override `{key}` has a non-UTF-8 value"
                )));
            };
            let mut parts = rest.splitn(2, "__");
            let (Some(idx_str), Some(field)) = (parts.next(), parts.next()) else {
                return Err(Self::s3_env_err(format!(
                    "malformed S3 bucket env override `{key}` \
                     (expected `{PREFIX}<index>__<FIELD>`)"
                )));
            };
            let idx: usize = idx_str.parse().map_err(|_| {
                Self::s3_env_err(format!(
                    "invalid S3 bucket index in `{key}` (expected a non-negative integer)"
                ))
            })?;
            overrides
                .entry(idx)
                .or_default()
                .push((field.to_ascii_lowercase(), value.to_owned()));
        }
        if overrides.is_empty() {
            return Ok(());
        }
        let buckets = &mut s3.get_or_insert_with(S3Config::default).buckets;
        for (idx, fields) in overrides {
            if idx > buckets.len() {
                return Err(Self::s3_env_err(format!(
                    "S3 bucket env override for index {idx} has no preceding bucket \
                     {} (define buckets contiguously from index 0)",
                    idx - 1
                )));
            }
            if idx == buckets.len() {
                buckets.push(S3Bucket::default());
            }
            let bucket = &mut buckets[idx];
            Self::apply_s3_bucket_fields(bucket, idx, &fields)?;
        }
        Ok(())
    }

    /// Apply the collected env-string field overrides onto one [`S3Bucket`] by
    /// round-tripping through the struct's own serde impl: serialize the bucket,
    /// patch each provided field onto its JSON object (coercing to the field's type
    /// learned from a fully-populated probe), then deserialize back.
    ///
    /// This is struct-driven: a newly-added `S3Bucket` field becomes env-settable as soon as
    /// it is added to the probe below, and the probe is a struct literal, so the compiler
    /// forces that. `deny_unknown_fields` on `S3Bucket`, plus the explicit probe-key check,
    /// reject a misspelled field loudly. There is no hand-maintained per-field `match` arm
    /// that could drift from the struct and leave a new field silently unsettable.
    ///
    /// # Errors
    ///
    /// Returns a boxed [`figment::Error`] on an unknown field name or a value that
    /// does not parse to a `bool` / integer field's type.
    fn apply_s3_bucket_fields(
        bucket: &mut S3Bucket,
        idx: usize,
        fields: &[(String, String)],
    ) -> Result<(), Box<figment::Error>> {
        let probe = s3_bucket_env_probe();
        let Ok(serde_json::Value::Object(types)) = serde_json::to_value(&probe) else {
            return Err(Self::s3_env_err(
                "internal: S3Bucket did not serialize to a JSON object".to_owned(),
            ));
        };
        let mut json = serde_json::to_value(&*bucket).map_err(|e| {
            Self::s3_env_err(format!(
                "S3 bucket {idx}: serialization for env overlay failed: {e}"
            ))
        })?;
        let serde_json::Value::Object(obj) = &mut json else {
            return Err(Self::s3_env_err(format!(
                "S3 bucket {idx}: expected a JSON object"
            )));
        };
        for (field, raw) in fields {
            let Some(exemplar) = types.get(field) else {
                return Err(Self::s3_env_err(format!(
                    "unknown S3 bucket field `{field}` in `GDI_NODE__S3__BUCKETS__{idx}__...` \
                     (S3Bucket has no such field)"
                )));
            };
            let coerced = match exemplar {
                serde_json::Value::Bool(_) => {
                    serde_json::Value::Bool(raw.parse::<bool>().map_err(|_| {
                        Self::s3_env_err(format!(
                            "S3 bucket {idx} field `{field}` must be `true` or `false`, got `{raw}`"
                        ))
                    })?)
                }
                serde_json::Value::Number(_) => serde_json::Value::Number(
                    raw.parse::<u64>()
                        .map_err(|_| {
                            Self::s3_env_err(format!(
                                "S3 bucket {idx} field `{field}` must be a non-negative integer, got `{raw}`"
                            ))
                        })?
                        .into(),
                ),
                _ => serde_json::Value::String(raw.clone()),
            };
            obj.insert(field.clone(), coerced);
        }
        *bucket = serde_json::from_value(json).map_err(|e| {
            Self::s3_env_err(format!(
                "S3 bucket {idx}: applying env overrides failed: {e}"
            ))
        })?;
        Ok(())
    }

    /// Box a figment error carrying an S3-bucket-env-override message.
    fn s3_env_err(message: String) -> Box<figment::Error> {
        Box::new(figment::Error::from(message))
    }

    /// Reject a config that still carries any `<SET ME …>` quickstart placeholder,
    /// listing every offending field so `check-config` yields the whole checklist in
    /// one pass rather than one field per re-run. Run first in [`Self::preflight`] so
    /// its message wins over the generic format checks a placeholder would also trip.
    ///
    /// # Errors
    /// [`CoreError::InvalidConfig`] if any string field still holds
    /// [`PLACEHOLDER_SENTINEL`]. Only the field paths are reported, never the values, which
    /// may be secrets.
    fn preflight_no_placeholders(&self) -> CoreResult<()> {
        // Serialize once and walk every string leaf, so this covers every serialized field
        // without a hand-maintained list.
        //
        // Not every field: anything carrying `#[serde(skip_serializing)]` is absent from this
        // JSON by construction and is invisible here. That is `vault.token` and
        // `vault.secret_id`, the two highest-consequence values in the config, which
        // `preflight_vault` therefore sentinel-checks by hand. A third skipped field must be
        // checked there too; `skip_serializing_fields_are_all_placeholder_checked` fails
        // until it is.
        let json = serde_json::to_value(self)
            .map_err(|e| invalid_config(&format!("could not inspect config: {e}")))?;
        let mut hits = Vec::new();
        collect_placeholder_paths("", &json, &mut hits);
        if hits.is_empty() {
            return Ok(());
        }
        Err(invalid_config(&format!(
            "config still contains unreplaced `{PLACEHOLDER_SENTINEL} ...>` placeholder(s); \
             set these fields before starting: {}",
            hits.join(", ")
        )))
    }

    /// Validate the resolved config before the listener binds (fail-fast).
    ///
    /// Runs the subset of cross-checks implementable now:
    /// - `base_url` is non-empty and parses as an absolute URL;
    /// - the five optional Beacon `/info` links (`documentation_url`, `alternative_url`,
    ///   `organization.welcome_url`, `organization.contact_url`, `organization.logo_url`)
    ///   pass the same http/https scheme rule as `base_url`; `contact_url` additionally
    ///   accepts a well-formed `mailto:` address;
    /// - `management_addr` is non-empty and differs from `listen` (else the health
    ///   probes, dataset-state oracle, and metrics would share the public surface);
    /// - `listen` and `management_addr` parse as `host:port` socket addresses
    ///   (fail-fast instead of crash-looping at `TcpListener::bind`);
    /// - `data_dir` is set and absolute (a relative value would root the data tree
    ///   under the process CWD; empty fails late at `create_dir_all`);
    /// - the four closed GA4GH beacon enums (`default_granularity`,
    ///   `production_status`, `security_level`, `environment`) are within their
    ///   allowed sets;
    /// - `request_timeout_seconds <= shutdown_drain_seconds` (a per-request
    ///   timeout must fit inside the shutdown drain);
    /// - when `[fairdp]` is present (the node serves FDP): the publisher and HDAB
    ///   contact points are complete, the theme/license/applicableLegislation/
    ///   contact IRIs and emails are well-formed, and the configured themes share
    ///   one SKOS scheme — overridden, if set, by `theme_taxonomy`, against which
    ///   every theme must be in-scheme (see `ServiceConfig::preflight_fairdp`).
    ///
    /// At least one catalog is recommended but not required, since a keyless inbox-only
    /// node may run with zero datasets, so it is deliberately not enforced here.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidConfig`] naming the offending key in the
    /// closed, path-free vocabulary on the first failing check.
    pub fn preflight(&self) -> CoreResult<()> {
        self.preflight_no_placeholders()?;
        check_non_empty("service.base_url", &self.service.base_url)?;
        let Ok(parsed_base) = url::Url::parse(&self.service.base_url) else {
            return Err(CoreError::InvalidConfig {
                detail: "service.base_url is not a valid URL".to_owned(),
            });
        };
        // "A valid URL" is not the test every other served IRI passes. `base_url` becomes
        // the subject IRI of every FDP record the node publishes, so a
        // `javascript:`/`data:`/`file:` value would be handed to whatever renders those
        // records as a link — the reason the scheme allow-list exists for the fields beside
        // it.
        if !matches!(parsed_base.scheme(), "http" | "https") {
            return Err(CoreError::InvalidConfig {
                detail: format!(
                    "service.base_url scheme {:?} is not allowed (expected http or https); it \
                     is the subject IRI of every published record",
                    parsed_base.scheme()
                ),
            });
        }
        // `base_url` is the subject IRI of every FDP-root/Catalog/Dataset record and is
        // emitted verbatim into `<…>` in the served Turtle, so it must carry no
        // IRIREF-forbidden character — the same guard the package path applies.
        if let Some(c) = crate::validate_pkg::find_iri_unsafe_char(&self.service.base_url) {
            return Err(CoreError::InvalidConfig {
                detail: format!(
                    "service.base_url contains a character not allowed in an IRI ({c:?})"
                ),
            });
        }
        // The five optional `/info` links pass the same scheme rule as `base_url` — all
        // five, or none: validating two would teach a reader the other three are checked too.
        Self::preflight_info_urls(&self.beacon)?;
        check_non_empty("service.management_addr", &self.service.management_addr)?;
        if self.service.management_addr == self.service.listen {
            return Err(CoreError::InvalidConfig {
                detail: "service.management_addr must not equal service.listen".to_owned(),
            });
        }
        // Bind-address parse + `data_dir` shape (extracted to keep this fn small).
        Self::preflight_service_bind(&self.service)?;
        // Public-plane CORS allow-list shape (extracted likewise).
        Self::preflight_cors(&self.service)?;
        // The four GA4GH-closed beacon enum fields (extracted likewise).
        Self::preflight_beacon_enums(&self.beacon.configuration, &self.beacon.environment)?;
        // The two beacon mount base paths are emitted verbatim (un-normalized) into
        // the `/map` `rootUrl` and the FDP `dcat:accessURL`/`dcat:endpointURL`, while
        // the router mounts the routes at `app::normalize_prefix(..)` of them. Require
        // each to already be in canonical mount form so the advertised discovery URL
        // is exactly the served route — a non-canonical value (`beacon/v2`,
        // `/beacon/v2/`, ``) would otherwise make the node advertise an endpoint it
        // 404s on while `/health` stays green.
        Self::preflight_base_path(
            "beacon.aggregated_base_path",
            &self.beacon.aggregated_base_path,
        )?;
        Self::preflight_base_path(
            "beacon.sensitive_base_path",
            &self.beacon.sensitive_base_path,
        )?;
        // Pin `api_version` to the vendored framework version (see
        // `SUPPORTED_BEACON_API_VERSION`): the informational responses hardcode that
        // version in their `$schema` / `partOfSpecification` literals, so a divergent
        // value would advertise a non-existent schema tree.
        if self.beacon.api_version != SUPPORTED_BEACON_API_VERSION {
            return Err(invalid_config(&format!(
                "beacon.api_version must be {SUPPORTED_BEACON_API_VERSION:?} (the vendored GA4GH framework version this node is pinned to)"
            )));
        }
        // Required beacon identity strings + OTLP endpoint validation (extracted to keep
        // this fn small).
        self.preflight_identity_and_otlp()?;
        // `[catalogs]` map keys become public `/fairdp` root IRIs via
        // `NamedNode::new_unchecked`, so an unsafe key (space, control char, `..`) would emit
        // SHACL-non-conformant RDF a harvester silently rejects while `/health` stays green.
        // Dataset-side catalog values must match one of these keys (`validate_catalog`), so
        // validating the keys secures both.
        for (key, title) in &self.catalogs {
            if !is_safe_catalog_name(key) {
                return Err(CoreError::InvalidConfig {
                    detail: format!(
                        "[catalogs] key {key:?} is not a valid catalog name (allowed: ASCII alphanumerics and `-_.`, at most {MAX_CATALOG_LEN} chars, no leading dot or `..`)"
                    ),
                });
            }
            // The catalog title value is emitted verbatim as the Catalog record's
            // `dct:title`/`dct:description`. An empty (or whitespace-only) value serves a
            // blank-titled `dcat:Catalog` — SHACL-conformant (the shapes carry no
            // `minLength`) but useless in the userportal — while `/health` stays green.
            // Reject it, mirroring the provider path which rejects an empty dataset title.
            if title.trim().is_empty() {
                return Err(CoreError::InvalidConfig {
                    detail: format!("[catalogs] title for {key:?} must not be empty"),
                });
            }
        }
        // All numeric zero-value + coherence bounds (request/package/parquet caps and
        // beacon pagination) — extracted to keep this fn small.
        Self::preflight_numeric_bounds(self)?;
        // Fail-closed writer-key enforcement must not boot with an empty allow-list on a
        // channel (it would silently reject every encrypted package there) unless the
        // operator has explicitly acknowledged it — the same ack posture as the k-anon floor.
        self.preflight_writer_policy()?;
        // The control endpoints must stay paced. `0` is refused rather than silently clamped:
        // an operator who wrote it meant "no limit", and clamping would leave them believing
        // they had it. Checked even when `[control].enabled` is false, so the value is
        // validated where it is written rather than only where it is used.
        if self.control.min_interval_seconds == 0 {
            return Err(CoreError::InvalidConfig {
                detail: "[control].min_interval_seconds must be at least 1: the operator \
                         action endpoints are rate-limited by design (each does real work: a \
                         config parse, a full reconcile). To turn them off entirely set \
                         [control].enabled = false"
                    .to_owned(),
            });
        }
        // Same reasoning: the bounded window is the control, so a zero-length one is a
        // contradiction rather than an off switch.
        if self.control.log_level_revert_seconds == 0 {
            return Err(CoreError::InvalidConfig {
                detail: "[control].log_level_revert_seconds must be at least 1: diagnostic \
                         logging reverts on a timer so it cannot be left on, and a zero-length \
                         window would revert before anything could be observed. To turn the \
                         endpoints off entirely set [control].enabled = false"
                    .to_owned(),
            });
        }
        // The advisory warnings for the k-anonymity floor and the blocking-pool pressure are
        // not emitted here. They are boot-time posture warnings for restart-only settings and
        // live in `emit_startup_advisories`, so a SIGHUP config reload — which re-runs
        // preflight on the candidate config, then rejects any restart-only change — does not
        // re-fire a k-anonymity alarm on a node whose effective floor never changed.
        // Validate every [[s3.buckets]] entry (extracted to keep this fn small).
        Self::preflight_s3_buckets(self)?;
        if let Some(vault) = &self.vault {
            Self::preflight_vault(
                vault,
                &self.beacon.environment,
                &self.beacon.configuration.production_status,
            )?;
        }
        if let Some(fairdp) = &self.fairdp {
            Self::preflight_fairdp(fairdp)?;
        }
        Ok(())
    }

    /// Emit the boot-time posture advisories for restart-only settings — the disabled
    /// k-anonymity floor and the blocking-pool pressure. Separate from [`Self::preflight`],
    /// which is pure validation, so only the boot and `check-config` paths fire them: a
    /// SIGHUP reload re-runs preflight on the candidate config and would otherwise re-raise
    /// the k-anonymity alarm for a floor change it then refuses to apply.
    pub fn emit_startup_advisories(&self) {
        // A disabled node-level k-anonymity floor is an auditable startup decision, and a
        // warning rather than an error: a zero floor is a valid DPIA-backed posture. See
        // `suppression_disabled_warning`.
        if let Some(msg) = suppression_disabled_warning(self.beacon.min_allele_count) {
            tracing::warn!("{msg}");
        }
        // A bucket allow-listing more than one writer key is the shared-bucket posture the
        // unsigned state sidecar makes hazardous — see `shared_bucket_writer_warning`.
        for bucket in self.s3.iter().flat_map(|s3| &s3.buckets) {
            if let Some(msg) =
                shared_bucket_writer_warning(&bucket.name, bucket.allowed_writer_fingerprints.len())
            {
                tracing::warn!("{msg}");
            }
        }
        // The read path's worst-case blocking-pool demand vs the shared tokio pool.
        if let Some(msg) = blocking_pool_pressure_warning(
            self.service.max_concurrent_requests,
            self.service.ingest_concurrency,
        ) {
            tracing::warn!("{msg}");
        }
        // The governance trail being off is at least as consequential as a disabled floor.
        if let Some(msg) = audit_disabled_warning(self.audit.enabled) {
            tracing::warn!("{msg}");
        }
        // The beacon id is what the GDI User Portal integrates against, and it restates
        // `environment` — a naming convention plus a second copy of a fact, so advisory
        // rather than fatal.
        if let Some(msg) = beacon_id_convention_warning(&self.beacon.id, &self.beacon.environment) {
            tracing::warn!("{msg}");
        }
    }

    /// Validate every `[[s3.buckets]]` entry: a non-empty, unique name (the name keys
    /// credentials, channel ownership and metric labels, so a duplicate silently collides
    /// all three), both-or-neither inline credentials, and a production `allow_http`
    /// man-in-the-middle warning. Extracted to keep [`Self::preflight`] under the line
    /// limit.
    ///
    /// # Errors
    /// A [`CoreError::InvalidConfig`] naming the first offending bucket.
    #[expect(
        clippy::too_many_lines,
        reason = "one loop of independent per-bucket assertions, each carrying the failure it \
                  prevents; splitting them would separate a check from its rationale"
    )]
    fn preflight_s3_buckets(&self) -> CoreResult<()> {
        let Some(s3) = &self.s3 else {
            return Ok(());
        };
        let mut seen_names = std::collections::BTreeSet::new();
        let mut seen_keyspaces: Vec<&S3Bucket> = Vec::new();
        for bucket in &s3.buckets {
            if bucket.name.is_empty() {
                return Err(invalid_config("an [[s3.buckets]] entry has an empty name"));
            }
            // The name is also the suppression-channel key: `channel hide` / `channel
            // take-down` write `channel-<name>.json` through
            // `suppression::channel_file_path`, which enforces its own grammar. Checking it
            // here reuses that one definition rather than restating it, and covers every
            // name-producing path that goes through preflight. Rejecting at boot keeps the
            // failure away from the moment an operator reaches for an emergency take-down,
            // where it would write no override file and withhold nothing.
            //
            // `inbox` is reserved for the local drop directory, and the collision is not
            // cosmetic: `writer_allowlist_for` short-circuits on `channel == "inbox"` and
            // returns `[ingest].inbox_allowed_writer_fingerprints` before it looks at the
            // buckets. A bucket named `inbox` therefore inherits the local inbox's
            // allow-list, so under `writer_policy = "enforce"` a package from that provider
            // signed by the local key is admitted while a legitimately-signed provider
            // package is quarantined — the cross-channel trust bleed the per-channel
            // allow-list exists to prevent. It also blinds the `WriterPolicy::Off` advisory,
            // since an inert but populated bucket list boots green whenever the inbox list is
            // empty. `is_valid_channel_name` accepts `inbox`, which is a legitimate
            // suppression channel, so the reservation is asserted here, where bucket names
            // are minted.
            if bucket.name == "inbox" {
                return Err(invalid_config(
                    "[[s3.buckets]] name \"inbox\" is reserved for the local inbox channel: a \
                     bucket with that name would inherit [ingest].inbox_allowed_writer_fingerprints \
                     instead of its own allowed_writer_fingerprints. Rename the bucket.",
                ));
            }
            if !crate::suppression::is_valid_channel_name(&bucket.name) {
                return Err(CoreError::InvalidConfig {
                    detail: format!(
                        "[[s3.buckets]] name {:?} cannot be used as a suppression channel \
                         (max 128 bytes, not \".\" or \"..\", and no '/', '\\\\' or NUL), so \
                         `channel hide` / `channel take-down` could not act on this channel",
                        bucket.name
                    ),
                });
            }
            // Bucket `name` is the key for Vault-backed credentials, channel ownership and
            // metric labels, so a duplicate silently collides all three — a plausible
            // copy-paste slip when hand-maintaining many per-provider buckets. Reject it
            // rather than boot green with a hidden collision.
            if !seen_names.insert(bucket.name.as_str()) {
                return Err(CoreError::InvalidConfig {
                    detail: format!(
                        "duplicate [[s3.buckets]] name {:?}: channel names must be unique",
                        bucket.name
                    ),
                });
            }
            // A duplicate keyspace under two different names is worse than a duplicate name.
            // This is the predicate `added_bucket_may_start` calls on the reload path,
            // applied here too so boot and reload agree.
            //
            // The failure it prevents is a silently undone take-down, most easily reached by
            // a half-finished rename: the reload refuses one and tells the operator to
            // restart, and the restart must not accept both names. Dataset D lands owned by
            // channel A; `channel take-down A` writes a Remove suppression and
            // `enforce_suppressions` erases D from cache, status and disk. Within
            // `full_poll_interval` channel B lists the same still-present object, evaluates
            // the channel suppression under its own name so it does not match, finds no owner
            // because the status row was just purged, and re-ingests and republishes D, while
            // `channel-A.json` still reads as in force.
            if let Some(twin) = seen_keyspaces
                .iter()
                .find(|other| !bucket.addresses_different_keyspace_than_ignoring_name(other))
            {
                return Err(CoreError::InvalidConfig {
                    detail: format!(
                        "[[s3.buckets]] entries {:?} and {:?} address the same keyspace \
                         (endpoint {:?}, bucket {:?}, prefix {:?}). Channel suppression is \
                         keyed by name, so a `channel take-down` of one is silently undone \
                         by the other re-ingesting the same objects. Give each provider its \
                         own bucket/prefix, or delete the duplicate entry (if this is a \
                         half-finished rename, remove the old name)",
                        twin.name, bucket.name, bucket.endpoint, bucket.bucket, bucket.prefix
                    ),
                });
            }
            seen_keyspaces.push(bucket);
            // The staleness bound must exceed the cadence at which the clock it measures
            // actually advances. `record_reconcile` has exactly one production caller, inside
            // `if should_reconcile(..)`, so in the steady state visibility freshness ticks
            // once per `full_poll_interval` — the marker HeadObject does not record it.
            //
            // The field reads as a reachability bound, which invites an operator wanting
            // faster retraction detection to set it at or below the poll interval. At 60 with
            // a 300 s poll the channel is stale for most of every cycle, and while stale
            // `fresh_visible_datasets` drops every dataset of the channel: /g_variants returns
            // nothing, /datasets is empty, /fairdp lists empty catalogs — all HTTP 200, with
            // `ready: true, degraded: false`, no metric for the gate, and the only signal a
            // field on the loopback management oracle.
            //
            // The bound is service-level and the cadence is per bucket, so the check runs per
            // bucket: one slow-polling channel is enough to blank itself.
            let staleness = self.service.max_visibility_staleness_seconds;
            let cadence = bucket
                .full_poll_interval
                .saturating_add(bucket.marker_poll_interval);
            if staleness > 0 && staleness <= cadence {
                return Err(CoreError::InvalidConfig {
                    detail: format!(
                        "[service].max_visibility_staleness_seconds {staleness} is at or below \
                         the poll cadence of [[s3.buckets]] {:?} (full_poll_interval {} + \
                         marker_poll_interval {} = {cadence}). The staleness clock advances \
                         only on a reconcile, so that channel would report stale for most of \
                         every cycle, and while stale every dataset it owns drops out of \
                         /g_variants, /datasets and /fairdp, as empty HTTP 200s, with \
                         /health/ready still reporting ready and not degraded. Raise it above \
                         {cadence}, with headroom for a slow listing delaying the reconcile \
                         (the default 86400 is a reachability bound, not a freshness target), \
                         or lower this channel's full_poll_interval",
                        bucket.name, bucket.full_poll_interval, bucket.marker_poll_interval,
                    ),
                });
            }
            // `endpoint` and `bucket` are unconditionally required: `s3_conn::S3ConnParams`
            // takes both as `&str`, so an entry missing either cannot build a client at all.
            // Rejecting here rather than at first poll keeps the failure visible — in the
            // service the client-build error only logs a warning and drops the bucket, and
            // `check-config` must not call such a config valid.
            for (field, value, hint) in [
                (
                    "endpoint",
                    &bucket.endpoint,
                    "there is no AWS-default fallback; give the regional endpoint explicitly, \
                     e.g. https://s3.eu-north-1.amazonaws.com",
                ),
                (
                    "bucket",
                    &bucket.bucket,
                    "this is the bucket name on that endpoint",
                ),
            ] {
                if value.as_deref().is_none_or(|v| v.trim().is_empty()) {
                    return Err(CoreError::InvalidConfig {
                        detail: format!(
                            "s3 channel {:?} is missing a non-empty {field}: it is required for \
                             every [[s3.buckets]] entry ({hint})",
                            bucket.name
                        ),
                    });
                }
            }
            // A prefix that does not survive `object_store::path::Path` normalization
            // unchanged addresses a different keyspace than the operator wrote — see
            // `validate_bucket_prefix` for why that is a boot rejection.
            validate_bucket_prefix(&bucket.name, &bucket.prefix)?;
            // Inline credentials are both-or-neither: a half-credential is silently
            // dropped or yields an opaque auth error at first poll.
            if bucket.access_key_id.is_some() != bucket.secret_access_key.is_some() {
                return Err(CoreError::InvalidConfig {
                    detail: format!(
                        "s3 bucket {} sets only one of access_key_id / secret_access_key; \
                         set both for inline credentials, or neither",
                        bucket.name
                    ),
                });
            }
            // The converse of the plaintext warning below: an `http://` endpoint with no
            // `allow_http`. `object_store` refuses to build the client, and its error
            // (`Generic S3 error: ... HTTP error: builder error`) names neither the scheme,
            // TLS, nor `allow_http`. The node holds both facts here, so it says the useful
            // sentence instead, as the Vault guard does for a plaintext address.
            //
            // A rejection rather than a warning: the bucket cannot work at all in this state,
            // so accepting the config would only move the failure to first poll, where the
            // service logs a warning and silently drops the bucket.
            if let Some(endpoint) = bucket.endpoint.as_deref()
                && endpoint
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("http://")
                && !bucket.allow_http
            {
                return Err(CoreError::InvalidConfig {
                    detail: format!(
                        "s3 bucket {:?} has a plaintext http:// endpoint ({endpoint}) but \
                         allow_http is false, so no client can be built for it. Use an https:// \
                         endpoint, or set allow_http = true on this bucket to opt into plaintext \
                         (intended for a loopback / in-cluster dev backend such as MinIO or \
                         Garage; see the plaintext warning for why not in production)",
                        bucket.name
                    ),
                });
            }
            // `allow_http` fetches packages, state and overlays over plaintext HTTP.
            // With no producer-authenticity check and a length-only download
            // verify, a network MITM on a non-loopback endpoint can inject a same-length
            // body. Warn (not reject — it is an explicit opt-in) in a prod environment; a
            // loopback / in-cluster dev backend is the legitimate case.
            if bucket.allow_http
                && is_production(
                    &self.beacon.environment,
                    &self.beacon.configuration.production_status,
                )
                && bucket
                    .endpoint
                    .as_deref()
                    .is_some_and(|e| !host_is_loopback(e))
            {
                tracing::warn!(
                    channel = %bucket.name,
                    endpoint = bucket.endpoint.as_deref().unwrap_or(""),
                    "s3 bucket uses allow_http (plaintext) against a non-loopback endpoint in a \
                     prod environment; a network MITM can inject packages/state (no producer \
                     authenticity, length-only download check). Prefer https or restrict the \
                     ingest network path."
                );
            }
        }
        Ok(())
    }

    /// Reject numeric knobs whose zero (or incoherent) values would boot green,
    /// pass `check-config`, and keep `/health` at 200 — yet silently break the data
    /// plane. Grouped out of [`Self::preflight`] so each family reads together.
    ///
    /// # Errors
    /// A [`CoreError::InvalidConfig`] naming the first offending field.
    fn preflight_numeric_bounds(&self) -> CoreResult<()> {
        // Request bounds: `ConcurrencyLimitLayer::new(0)` sheds every request (503) and
        // a 0-second timeout times out every request (408); a 0 body cap
        // (`DefaultBodyLimit::max(0)`) 413s every POST beacon query.
        //
        // Not validated here, because they are `.max(1)`-floored at their use site, where a
        // `0` is treated as `1` with no busy-loop or deadlock: shutdown_drain (`main.rs`),
        // rescan_interval (`main.rs`), startup_reconcile_timeout (`main.rs`),
        // marker_poll_interval and full_poll_interval (`s3.rs`), and ingest_concurrency
        // (`ingest_runtime.rs` / `s3.rs`). None of these treat `0` as "disabled"; only
        // `rejected_retention_hours` and `rejected_max_count` do (see their field docs).
        if self.service.request_timeout_seconds == 0 {
            return Err(invalid_config(
                "service.request_timeout_seconds must be at least 1",
            ));
        }
        if self.service.max_concurrent_requests == 0 {
            return Err(invalid_config(
                "service.max_concurrent_requests must be at least 1",
            ));
        }
        if self.service.max_query_bytes == 0 {
            return Err(invalid_config(
                "service.max_query_bytes must be at least 1 (it is the aggregate scan-row heap \
                 ceiling; 0 would reject every query)",
            ));
        }
        if self.service.max_query_rows == 0 {
            return Err(invalid_config(
                "service.max_query_rows must be at least 1 (it is the per-dataset scan-row \
                 ceiling; 0 would reject every query)",
            ));
        }
        if self.service.query_concurrency == Some(0) {
            return Err(invalid_config(
                "service.query_concurrency must be at least 1 when set (it is the per-query \
                 scan fan-out cap; 0 would admit no scans). Omit it to follow \
                 ingest_concurrency",
            ));
        }
        if self.service.max_total_query_bytes < self.service.max_query_bytes {
            return Err(invalid_config(
                "service.max_total_query_bytes must be >= service.max_query_bytes: the \
                 process-wide scan-row budget cannot be smaller than what a single request \
                 is allowed to retain, or no query could ever be admitted",
            ));
        }
        // Each of these documents `0` as "unbounded" and points at the other as the bound
        // that still applies. Both at zero therefore removes every limit on the quarantine
        // directory, which grows by a full rejected package per bad drop, forever, on the
        // same volume the served datasets live on — and neither field alone can notice.
        if self.service.rejected_retention_hours == 0 && self.service.rejected_max_count == 0 {
            return Err(invalid_config(
                "service.rejected_retention_hours and service.rejected_max_count are both 0: \
                 each means \"unbounded\" and relies on the other to bound the quarantine \
                 directory, so setting both leaves it to grow without limit. Set at least one",
            ));
        }
        if self.service.max_request_body_bytes == 0 {
            return Err(invalid_config(
                "service.max_request_body_bytes must be at least 1",
            ));
        }
        // Package + parquet caps: a 0 package cap rejects every package permanently
        // (the decrypt counting writer trips on the first byte, the extract bounds on
        // the first member); a 0 parquet cap rejects every non-empty data file (strict
        // `>` in `validate_parquet`) — fail-closed, but a silent serve-nothing footgun.
        if self.service.max_package_bytes == 0 {
            return Err(invalid_config(
                "service.max_package_bytes must be at least 1",
            ));
        }
        if self.service.max_package_members == 0 {
            return Err(invalid_config(
                "service.max_package_members must be at least 1",
            ));
        }
        if self.service.max_parquet_file_bytes == 0 {
            return Err(invalid_config(
                "service.max_parquet_file_bytes must be at least 1",
            ));
        }
        if self.service.max_parquet_decompressed_bytes == 0 {
            return Err(invalid_config(
                "service.max_parquet_decompressed_bytes must be at least 1",
            ));
        }
        if self.service.max_parquet_row_group_bytes == 0 {
            return Err(invalid_config(
                "service.max_parquet_row_group_bytes must be at least 1",
            ));
        }
        if self.service.request_timeout_seconds > self.service.shutdown_drain_seconds {
            return Err(invalid_config(
                "service.request_timeout_seconds must not exceed service.shutdown_drain_seconds",
            ));
        }
        // Beacon pagination: `apply_pagination` clamps every explicit limit to
        // `max_page_limit` (the `Some(0)` "unbounded" sentinel resolves to it too) and
        // falls back to `default_page_limit` when omitted — so a `0` on either knob
        // makes every `g_variants`/`datasets` page return 0 records, and a `default`
        // above `max` is incoherent (silently clamped down at the use site).
        if self.beacon.max_page_limit == 0 {
            return Err(invalid_config("beacon.max_page_limit must be at least 1"));
        }
        if self.beacon.default_page_limit == 0 {
            return Err(invalid_config(
                "beacon.default_page_limit must be at least 1",
            ));
        }
        if self.beacon.default_page_limit > self.beacon.max_page_limit {
            return Err(invalid_config(
                "beacon.default_page_limit must not exceed beacon.max_page_limit",
            ));
        }
        Ok(())
    }

    /// Require the GA4GH-mandatory beacon identity strings to be non-empty, and validate
    /// a set `otlp_endpoint`. Extracted from [`Self::preflight`] to keep it small.
    ///
    /// `beacon.id` and `beacon.name` are emitted verbatim into `/info` and `/service-info`
    /// and default to an empty string, which `preflight_no_placeholders` does not catch
    /// because it only trips on the `<SET ME` sentinel — so a blank value would advertise a
    /// nameless beacon while `/health` stays 200. The nested `organization.id`/`name` are
    /// also GA4GH-required but are not enforced here: doing so would reject the many valid
    /// minimal configurations a keyless or development node legitimately runs with.
    ///
    /// A set `otlp_endpoint` must be a well-formed URL, and a set
    /// `otlp_metrics_interval_seconds` must be at least 1. As with the Vault and S3 plaintext
    /// guards, a secret `otlp_headers` exported over plaintext `http://` to a non-loopback
    /// collector in production travels in cleartext, and warns.
    ///
    /// # Errors
    /// A [`CoreError::InvalidConfig`] naming the first offending field.
    fn preflight_identity_and_otlp(&self) -> CoreResult<()> {
        if self.service.otlp_metrics_interval_seconds == Some(0) {
            return Err(invalid_config(
                "service.otlp_metrics_interval_seconds must be at least 1; omit it to \
                 disable the OTLP metrics push",
            ));
        }
        if let Some(ratio) = self.service.otlp_trace_sample_ratio
            && !(0.0..=1.0).contains(&ratio)
        {
            return Err(invalid_config(
                "service.otlp_trace_sample_ratio must be between 0.0 and 1.0; omit it to \
                 export every trace",
            ));
        }
        for (field, value) in [
            ("beacon.id", &self.beacon.id),
            ("beacon.name", &self.beacon.name),
        ] {
            if value.is_empty() {
                return Err(invalid_config(&format!(
                    "{field} is required (GA4GH beaconInfoResults)"
                )));
            }
        }
        if let Some(endpoint) = &self.service.otlp_endpoint {
            let url = url::Url::parse(endpoint).map_err(|_| {
                invalid_config(
                    "service.otlp_endpoint must be a valid URL (e.g. http://collector:4318)",
                )
            })?;
            let has_secret_headers = self
                .service
                .otlp_headers
                .as_ref()
                .is_some_and(|h| !h.0.is_empty());
            if has_secret_headers
                && url.scheme() == "http"
                && is_production(
                    &self.beacon.environment,
                    &self.beacon.configuration.production_status,
                )
                && !host_is_loopback(endpoint)
            {
                tracing::warn!(
                    "service.otlp_headers carries a secret exported over plaintext http:// to a \
                     non-loopback service.otlp_endpoint in a prod environment, so the header \
                     travels in cleartext. Use an https:// endpoint (a `full` build verifies it \
                     against the OS CA bundle) or restrict the export network path."
                );
            }
        }
        Ok(())
    }

    /// Validate the public + management bind addresses and `data_dir` shape.
    ///
    /// Parses `listen` / `management_addr` as `host:port` socket addresses so a
    /// malformed value (a typo, a bare host, a hostname) fails `check-config`
    /// instead of crash-looping at `TcpListener::bind` — `SocketAddr` requires a
    /// numeric IP + port (the node never resolves hostnames for its own listeners),
    /// matching every shipped example (`0.0.0.0:PORT`, `[::]:PORT`). `data_dir` is
    /// required and must be absolute (empty fails late at `create_dir_all("")`; a
    /// relative value silently roots the data tree under the process CWD).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidConfig`] naming the first offending field.
    fn preflight_service_bind(service: &ServiceSection) -> CoreResult<()> {
        if service.listen.parse::<SocketAddr>().is_err() {
            return Err(invalid_config(
                "service.listen must be a host:port socket address (e.g. 0.0.0.0:8080)",
            ));
        }
        if service.management_addr.parse::<SocketAddr>().is_err() {
            return Err(invalid_config(
                "service.management_addr must be a host:port socket address (e.g. 0.0.0.0:9090)",
            ));
        }
        if service.data_dir.as_os_str().is_empty() {
            return Err(invalid_config("service.data_dir is required"));
        }
        if !service.data_dir.is_absolute() {
            return Err(invalid_config("service.data_dir must be an absolute path"));
        }
        // The override store holds operator take-downs/corrections that are not
        // reconstructible from the source bucket. A relative `override_dir` resolves against
        // the process working directory, so the operator CLI (run from a shell) and the node
        // (typically working directory `/`) would read different stores — a silent
        // confidentiality fail-open where a recorded take-down is never seen by the server.
        // Require the resolved root to be absolute; the default, `<data_dir>/overrides`,
        // already is, since `data_dir` is absolute above.
        if !service.override_dir_resolved().is_absolute() {
            return Err(invalid_config(
                "service.override_dir must be an absolute path: a relative value resolves \
                 against the process working directory, so the operator CLI and the node \
                 would read different override stores",
            ));
        }
        Self::reject_existing_non_directory("service.data_dir", &service.data_dir)?;
        if let Some(inbox) = service.inbox.as_deref() {
            Self::reject_existing_non_directory("service.inbox", inbox)?;
        }
        Ok(())
    }

    /// Reject a configured directory path that exists but is not a directory.
    ///
    /// Narrow by design. Preflight must stay runnable where the volume is not mounted:
    /// `check-config` is a pre-deploy gate, often run in CI on a box with none of the
    /// node's storage. So an absent path is not an error here, and this does not check
    /// writability either; both are startup concerns, and docs/operating.md says so.
    ///
    /// But a path that exists and is a regular file can never become a data dir or an inbox,
    /// on any host. Preflight already rejects a relative `data_dir`, so a filesystem-shaped
    /// check is in scope, and without this one `check-config` would report success for a
    /// config whose only possible outcome is a failed boot — the one verdict a pre-deploy
    /// gate must not give. The common way to reach it is a container or Kubernetes mount
    /// landing a file where a directory was meant.
    ///
    /// # Errors
    /// Returns an invalid-config error naming `field` when `path` exists and is not a dir.
    fn reject_existing_non_directory(field: &str, path: &Path) -> Result<(), CoreError> {
        // `symlink_metadata` would refuse a symlink pointing at a directory, which is a
        // legitimate deployment shape; follow it, as every later open() does.
        match std::fs::metadata(path) {
            Ok(meta) if !meta.is_dir() => Err(invalid_config(&format!(
                "{field} exists but is not a directory: {}. The node needs a directory \
                 there (a container mount landing a file is the usual cause)",
                path.display()
            ))),
            // Absent, or unreadable from here: not a preflight failure. A pre-deploy check
            // routinely runs where the volume is not mounted, and startup reports the real
            // problem with the real permissions.
            _ => Ok(()),
        }
    }

    /// Validate `[service].cors_allowed_origins` (the public-plane CORS allow-list).
    ///
    /// Empty (the default) is the wildcard `*` and needs no validation. A non-empty
    /// list must be either the single explicit wildcard `["*"]` or exact HTTP(S)
    /// origins: each entry must equal its own canonical origin serialization
    /// (`scheme://host[:port]`, lowercase, default port dropped, no path/query/fragment/
    /// credentials/trailing slash). That canonical form is exactly what a browser sends
    /// in the `Origin` header and what the CORS layer matches byte-for-byte, so a
    /// non-canonical value (trailing slash, explicit `:443`, uppercase scheme) would
    /// silently never match and quietly block the very clients it was meant to allow —
    /// fail fast at boot instead.
    ///
    /// # Errors
    /// [`CoreError::InvalidConfig`] on an empty entry, `"*"` mixed with specific
    /// origins, or an entry that is not a bare canonical HTTP(S) origin.
    fn preflight_cors(service: &ServiceSection) -> CoreResult<()> {
        let origins = &service.cors_allowed_origins;
        if origins.is_empty() {
            return Ok(());
        }
        if origins.iter().any(|o| o == "*") && origins.len() > 1 {
            return Err(invalid_config(
                "service.cors_allowed_origins: \"*\" (allow any origin) cannot be combined with \
                 specific origins; list either \"*\" alone or only exact origins",
            ));
        }
        for origin in origins {
            if origin == "*" {
                continue;
            }
            if origin.is_empty() {
                return Err(invalid_config(
                    "service.cors_allowed_origins contains an empty entry",
                ));
            }
            let Ok(url) = url::Url::parse(origin) else {
                return Err(invalid_config(&format!(
                    "service.cors_allowed_origins entry {origin:?} is not a valid origin \
                     (expected scheme://host[:port], e.g. https://portal.example.org)"
                )));
            };
            if !matches!(url.scheme(), "http" | "https") {
                return Err(invalid_config(&format!(
                    "service.cors_allowed_origins entry {origin:?} must use the http or https scheme"
                )));
            }
            // `Origin::ascii_serialization` yields the canonical `scheme://host[:port]`
            // (default ports dropped, scheme/host lowercased, no path). Requiring the
            // configured value to already equal it rejects trailing slashes, paths,
            // credentials, uppercase and explicit default ports in one comparison — and
            // guarantees the stored value matches the browser `Origin` header verbatim.
            let canonical = url.origin().ascii_serialization();
            if canonical != *origin {
                return Err(invalid_config(&format!(
                    "service.cors_allowed_origins entry {origin:?} is not a bare canonical origin; \
                     use {canonical:?} (scheme://host[:port], no path/trailing-slash/default-port)"
                )));
            }
        }
        Ok(())
    }

    /// Validate the four GA4GH-closed beacon enum fields, which are emitted verbatim
    /// into `/info`, `/service-info`, and `/configuration`.
    ///
    /// A typo yields a non-conformant response a registry/aggregator rejects, and a
    /// bad `default_granularity` also mis-routes the node default (only the *client*
    /// granularity is folded against the allowed set — the config default is not).
    /// `environment` is the GA4GH `beaconInfoResults` required closed enum
    /// (`prod|test|dev|staging`): an empty or mistyped value (`production`, `PROD`)
    /// makes `/info` fail the framework schema, so it is validated here too.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidConfig`] naming the first out-of-set field.
    fn preflight_beacon_enums(conf: &BeaconConfiguration, environment: &str) -> CoreResult<()> {
        if !matches!(
            conf.default_granularity.as_str(),
            "boolean" | "count" | "record"
        ) {
            return Err(invalid_config(
                "beacon.configuration.default_granularity must be one of: boolean, count, record",
            ));
        }
        if !matches!(conf.production_status.as_str(), "DEV" | "TEST" | "PROD") {
            return Err(invalid_config(
                "beacon.configuration.production_status must be one of: DEV, TEST, PROD",
            ));
        }
        if !matches!(
            conf.security_level.as_str(),
            "PUBLIC" | "REGISTERED" | "CONTROLLED"
        ) {
            return Err(invalid_config(
                "beacon.configuration.security_level must be one of: PUBLIC, REGISTERED, CONTROLLED",
            ));
        }
        if !matches!(environment, "prod" | "test" | "dev" | "staging") {
            return Err(invalid_config(
                "beacon.environment must be one of: prod, test, dev, staging",
            ));
        }
        Ok(())
    }

    /// Validate the five optional Beacon `/info` links against [`check_info_url`]: all
    /// five, or none — checking two would teach a reader the other three are checked too.
    /// `contact_url` alone accepts a well-formed `mailto:` address; the other four are web
    /// links and accept `http`/`https` only. Extracted (like its neighbours) to keep
    /// `preflight` itself under the line-count lint.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidConfig`] naming the offending link.
    fn preflight_info_urls(beacon: &BeaconConfig) -> CoreResult<()> {
        let org = &beacon.organization;
        for (field, value, allow_mailto) in [
            (
                "beacon.documentation_url",
                beacon.documentation_url.as_deref(),
                false,
            ),
            (
                "beacon.alternative_url",
                beacon.alternative_url.as_deref(),
                false,
            ),
            (
                "beacon.organization.welcome_url",
                org.welcome_url.as_deref(),
                false,
            ),
            (
                "beacon.organization.contact_url",
                org.contact_url.as_deref(),
                true,
            ),
            (
                "beacon.organization.logo_url",
                org.logo_url.as_deref(),
                false,
            ),
        ] {
            if let Some(value) = value {
                check_info_url(field, value, allow_mailto)?;
            }
        }
        Ok(())
    }

    /// Validate a beacon mount base path is in canonical mount form.
    ///
    /// The router mounts at the service crate's `normalize_prefix` of the value, but
    /// the value is also emitted verbatim into the `/map` `rootUrl` and the FDP
    /// `dcat:accessURL`/`dcat:endpointURL`. Requiring the stored value to already be
    /// canonical keeps all three in agreement. Canonical means: non-empty,
    /// starts with `/`, is not the lone root `/`, does not end with `/`, has no empty
    /// path segment (`//`), and contains no whitespace or control characters.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidConfig`] naming the field and the rule it broke.
    fn preflight_base_path(field: &str, path: &str) -> CoreResult<()> {
        // The canonical-mount-form rules, in the order the doc comment lists them; the
        // first one the value breaks names itself in the error.
        for (broken, rule) in [
            (path.is_empty(), "must not be empty (e.g. /beacon/v2)"),
            (
                !path.starts_with('/'),
                "must start with `/` (e.g. /beacon/v2)",
            ),
            (
                path == "/",
                "must name a path under root, not `/` itself (e.g. /beacon/v2)",
            ),
            (
                path.ends_with('/'),
                "must not end with `/` (e.g. /beacon/v2)",
            ),
            (
                path.contains("//"),
                "must not contain an empty path segment (`//`)",
            ),
            (
                path.chars().any(|c| c.is_whitespace() || c.is_control()),
                "must not contain whitespace or control characters",
            ),
        ] {
            if broken {
                return Err(invalid_config(&format!("{field} {rule}")));
            }
        }
        // The base path is emitted verbatim inside `<…>` in served DCAT/Turtle (it is part of
        // every aggregated resource IRI), so it must pass the same IRIREF char-set gate every
        // other served IRI does — otherwise `>` breaks out of the IRI and injects triples, and
        // other delimiters (`<`, `"`, `{}`, `|`, `\`, backtick, `^`) corrupt the graph. The
        // sibling `base_url` already routes through this; single-sourcing the check here means
        // both served-IRI inputs cannot diverge.
        if let Some(c) = crate::validate_pkg::find_iri_unsafe_char(path) {
            return Err(invalid_config(&format!(
                "{field} contains a character not allowed in an IRI ({c:?}); it is emitted \
                 verbatim into served DCAT/Turtle"
            )));
        }
        Ok(())
    }

    /// Validate the `[vault]` block (only reached when it is present).
    ///
    /// Feature-independent shape checks (the `--features vault` gating is the
    /// service-side feature preflight's job): `address` is a non-empty valid URL;
    /// `kv_path` is set (the identity source); auth is configured as exactly one of
    /// a static `token` or a complete `AppRole` (`role_id` + `secret_id`). The
    /// secret values themselves are not logged or echoed.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidConfig`] naming the offending `[vault]` key.
    fn preflight_vault(
        vault: &VaultConfig,
        environment: &str,
        production_status: &str,
    ) -> CoreResult<()> {
        check_non_empty("vault.address", &vault.address)?;
        let Ok(parsed_addr) = url::Url::parse(&vault.address) else {
            return Err(invalid_config("vault.address is not a valid URL"));
        };
        // Refuse a plaintext (non-https) Vault address to a non-loopback host on a
        // production node: the client token, AppRole secret_id and the Transit DEKs would all
        // transit in cleartext, so a copied development config (`http://vault:8200`) must not
        // silently ship secrets in the clear. "Production" is `environment == "prod"` or the
        // advertised `production_status == "PROD"`; gating on both closes the gap where a
        // node advertises PROD to clients yet sets `environment = dev`, a single
        // silently-overridable string, and downgrades this control to a no-op. A loopback
        // backend (a same-host sidecar) is exempt, mirroring the S3 `allow_http` opt-in.
        // Compare the parsed scheme, already lowercased by `url`, so a valid uppercase
        // `HTTPS://` is not false-rejected.
        if is_production(environment, production_status)
            && parsed_addr.scheme() != "https"
            && !host_is_loopback(&vault.address)
        {
            return Err(invalid_config(
                "vault.address must be https:// on a production node: a non-loopback plaintext \
                 address transits the token, AppRole secret_id, and Transit DEKs in cleartext. Use \
                 https, a loopback address, or set BOTH beacon.environment to dev/test/staging AND \
                 beacon.configuration.production_status to DEV/TEST",
            ));
        }
        // Two credential sources that can disagree is a misconfiguration, not something
        // to resolve with a silent precedence rule: the operator who set both cannot tell
        // which one the node is authenticating with, and the losing one looks live.
        //
        // Counted over all three file-configured methods, not just the token/token_file
        // pair: `token_file` beside AppRole is the natural shape of a half-finished migration
        // to an agent sidecar, and `resolve_auth`'s ordering would silently pick one while
        // the other looked live. Any AppRole material at all counts, so a leftover `role_id`
        // beside a new `token_file` is caught rather than ignored.
        let configured = vault.configured_auth_methods();
        if configured.len() > 1 {
            return Err(CoreError::InvalidConfig {
                detail: format!(
                    "vault auth methods are mutually exclusive, but {} are configured ({}); \
                     set exactly one. token_file is the agent-sidecar shape (an external agent \
                     refreshes the token, no static credential is stored); remove the others \
                     rather than relying on a precedence rule.",
                    configured.len(),
                    configured.join(", ")
                ),
            });
        }
        // A relative path resolves against the process CWD, which differs between a
        // systemd unit and a container — the same trap service.data_dir rejects.
        if let Some(path) = &vault.token_file
            && !path.is_absolute()
        {
            return Err(invalid_config(
                "vault.token_file must be an absolute path (a relative path would resolve \
                 against the process working directory)",
            ));
        }
        // Both credentials are `#[serde(skip_serializing)]`, so `preflight_no_placeholders`
        // cannot see them: an unreplaced `<SET ME: …>` is non-empty and would otherwise sail
        // through every check here and be sent to Vault as a literal token.
        check_no_placeholder("vault.token", vault.token.as_deref())?;
        check_no_placeholder("vault.secret_id", vault.secret_id.as_deref())?;
        check_non_empty("vault.kv_path", vault.kv_path.as_deref().unwrap_or(""))?;
        // A present-but-empty transit_key silently disables PME at-rest encryption
        // (the activation path treats empty as unset). Reject it so an at-rest
        // misconfig fails fast rather than booting with plaintext-at-rest; a node
        // that genuinely runs without PME omits transit_key entirely.
        if vault.transit_key.as_deref().is_some_and(str::is_empty) {
            return Err(invalid_config(
                "vault.transit_key is set but empty; omit it to run without PME, or set the key name",
            ));
        }
        let has_token = vault.token.as_deref().is_some_and(|t| !t.is_empty());
        // The runtime auth resolver (`vault::resolve_auth`) accepts the conventional bare
        // `VAULT_TOKEN` environment variable as a final fallback when neither `vault.token`
        // nor AppRole is set — a documented, supported bootstrap path. figment folds only
        // the prefixed `GDI_NODE__VAULT__TOKEN` into `vault.token`; a plain `VAULT_TOKEN`
        // never lands in the struct, so preflight must read the environment directly or it
        // aborts boot (and `check-config`) for a config `resolve_auth` would authenticate.
        let has_env_token = std::env::var_os("VAULT_TOKEN").is_some_and(|v| !v.is_empty());
        let has_role = vault.role_id.as_deref().is_some_and(|r| !r.is_empty());
        let has_secret_id = vault.secret_id.as_deref().is_some_and(|s| !s.is_empty());
        let has_approle = has_role && has_secret_id;
        // `token_file` is a complete auth method on its own: an external agent writes the
        // token there. Its existence is not checked at preflight, because the agent
        // sidecar may not have written it yet when the node's config is validated, and a
        // missing file surfaces as a clear permanent error on the first Vault call.
        let has_token_file = vault.token_file.is_some();
        // The bare `VAULT_TOKEN` fallback is not part of the exclusivity count above: it is
        // ambient process environment rather than something the operator wrote in this file,
        // and a boot must not fail because a shell exported it. It only matters here, where
        // nothing in the file supplies auth.
        if !has_token && !has_env_token && !has_approle && !has_token_file {
            // Neither complete auth method.
            if has_role || has_secret_id {
                return Err(invalid_config(
                    "vault AppRole auth needs both role_id and secret_id (or set vault.token)",
                ));
            }
            return Err(invalid_config(
                "vault needs auth: set vault.token (or VAULT_TOKEN), vault.token_file, or \
                 vault.role_id + vault.secret_id",
            ));
        }
        Ok(())
    }

    /// Whether the resolved config carries any `[[s3.buckets]]` entry.
    ///
    /// Used by the service-side feature preflight, which has the Cargo
    /// `cfg!(feature = "s3")` in scope unlike this crate, to reject an S3 config on a binary
    /// built without the `s3` feature.
    #[must_use]
    pub fn has_s3_buckets(&self) -> bool {
        self.s3.as_ref().is_some_and(|s3| !s3.buckets.is_empty())
    }

    /// The writer-key allow-list for a channel — a bucket's `name`, or `inbox`.
    ///
    /// Empty when the channel has no list (and thus, under `enforce`, admits no encrypted
    /// package). The trust boundary is the channel, so each bucket owns its own list.
    ///
    /// This reads `self`, the boot-loaded config, and is used at startup preflight, by
    /// `doctor` and in tests. The running node's ingest gate reads the live-reloadable mirror
    /// [`Reloadable::writer_allowlist_for`] instead, sourced from `AppState`'s
    /// `SIGHUP`-swappable cell rather than the immutable boot `Arc`.
    #[must_use]
    pub fn writer_allowlist_for(&self, channel: &str) -> &[String] {
        if channel == "inbox" {
            return &self.ingest.inbox_allowed_writer_fingerprints;
        }
        self.s3
            .as_ref()
            .and_then(|s3| s3.buckets.iter().find(|b| b.name == channel))
            .map_or(&[], |b| b.allowed_writer_fingerprints.as_slice())
    }

    /// Whether `new` differs from `self` in any field outside the `SIGHUP`-reloadable
    /// subset: `[catalogs]`, the `[ingest]` writer-key allow-list (see [`Reloadable`]), and
    /// an added or modified `[[s3.buckets]]` entry.
    ///
    /// Used by the `SIGHUP` config-reload handler to warn an operator whose reloaded file
    /// also touched a restart-only field (a listener, `[vault]`, `min_allele_count`, …) that
    /// the change was not applied.
    ///
    /// Implemented by copying `new`'s reloadable fields onto a clone of `self`, then
    /// comparing that against `new` via `Debug`, so the fields this function names are
    /// [`Reloadable::from_config`]'s — the same ones the swap itself extracts — plus
    /// `[ingest].allow_any_writer_ack`, rather than a second hand-maintained "restart-only
    /// fields" list that could drift from the first. The ack is not a [`Reloadable`] field
    /// because it holds no live state, being consulted only transiently by preflight
    /// (`preflight_writer_policy`, re-run on every reload), so a change to it needs no
    /// restart and is patched in here rather than raising a spurious warning.
    ///
    /// Buckets are patched where `new` still has the entry and it still addresses the same
    /// keyspace. A bucket that `new` adds, or modifies in an access or behaviour field, is
    /// applied live by the monitor reload, so it must not raise this warning. The two
    /// restart-only bucket edits survive the patch and still warn:
    ///
    /// * a bucket `new` removes — a vanished bucket is indistinguishable from a total mass
    ///   removal and collides with the cross-poll confirmation guard — and
    /// * a bucket whose `endpoint`/`bucket`/`prefix` changed — the same hazard reached by an
    ///   edit rather than a deletion (see [`S3Bucket::addresses_different_keyspace_than`]).
    ///
    /// Removal is detected by the surviving entry rather than by counting, so a reload that
    /// removes one bucket and adds another — same count, different set — still warns.
    #[must_use]
    pub fn changed_outside_reloadable_subset(&self, new: &Self) -> bool {
        let mut patched = self.clone();
        patched.catalogs.clone_from(&new.catalogs);
        patched.ingest.writer_policy = new.ingest.writer_policy;
        patched
            .ingest
            .allow_any_writer_ack
            .clone_from(&new.ingest.allow_any_writer_ack);
        patched
            .ingest
            .inbox_allowed_writer_fingerprints
            .clone_from(&new.ingest.inbox_allowed_writer_fingerprints);
        // One side missing `[s3]` entirely is left alone: adding or dropping the whole
        // section is not something the monitor reload handles, so it stays visible below.
        if let (Some(patched_s3), Some(new_s3)) = (patched.s3.as_mut(), new.s3.as_ref()) {
            // Take `new`'s descriptor for every bucket both sides declare, and append the
            // ones `new` adds. A bucket `new` removed is left in place: it is
            // then the one bucket-shaped difference this comparison can still see, which is
            // exactly the half that stays restart-only.
            for bucket in &mut patched_s3.buckets {
                if let Some(nb) = new_s3.buckets.iter().find(|nb| nb.name == bucket.name) {
                    // Only where the entry still addresses the same keyspace. An
                    // `endpoint`/`bucket`/`prefix` change is applied by neither half of the
                    // reload (the monitor reload leaves it alone — see `reload_s3_monitors`),
                    // so patching it here would hide the one restart-only bucket edit an
                    // operator is most likely to make and least likely to survive.
                    if !bucket.addresses_different_keyspace_than(nb) {
                        bucket.clone_from(nb);
                    }
                }
            }
            for nb in &new_s3.buckets {
                if !patched_s3.buckets.iter().any(|b| b.name == nb.name) {
                    patched_s3.buckets.push(nb.clone());
                }
            }
            // The patch can reorder relative to `new` (survivors keep the old order,
            // additions land at the end) and `Debug` is order-sensitive, which would report
            // a pure reordering as a restart-only change. Order carries no meaning for a
            // name-keyed bucket set, so both sides are compared sorted.
            patched_s3.buckets.sort_by(|a, b| a.name.cmp(&b.name));
        }
        let mut new_sorted = new.clone();
        if let Some(s3) = new_sorted.s3.as_mut() {
            s3.buckets.sort_by(|a, b| a.name.cmp(&b.name));
        }
        // `Debug` on `S3Bucket` redacts `secret_access_key`, so a pure credential rotation
        // is invisible here, which is correct: the monitor reload applies that change live,
        // so it must not warn. Removal, the half this still guards, is a whole missing entry
        // and stays visible.
        format!("{patched:?}") != format!("{new_sorted:?}")
    }

    /// Reject a self-contradictory writer-policy configuration, in either direction:
    ///
    /// * `enforce` with an empty allow-list on a configured ingest channel (unless
    ///   `allow_any_writer_ack` is set) — it would reject every encrypted package.
    /// * `off` with a non-empty allow-list on a configured ingest channel — `off` ignores
    ///   the list entirely, so a configured list gives a false sense of gating while every
    ///   writer is accepted. `warn` and `enforce` both consult the list, so only `off` is
    ///   refused here.
    /// * `enforce` on a keyless node (no `[keys].identities`, no `[vault]`) — it could never
    ///   verify a writer key, so every drop would be an unidentified plaintext staging dir
    ///   and be quarantined: the node would serve nothing, forever.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidConfig`] naming the first offending channel.
    fn preflight_writer_policy(&self) -> CoreResult<()> {
        // Channels that can ingest an encrypted package, in a stable order.
        let mut channels: Vec<&str> = Vec::new();
        if self.service.inbox.is_some() {
            channels.push("inbox");
        }
        if let Some(s3) = &self.s3 {
            channels.extend(s3.buckets.iter().map(|b| b.name.as_str()));
        }

        match self.ingest.writer_policy {
            // `off` gates nothing: a configured allow-list is inert. Refuse to boot rather than
            // silently ignore it — the operator almost certainly believes writer gating is on.
            WriterPolicy::Off => {
                for channel in &channels {
                    if !self.writer_allowlist_for(channel).is_empty() {
                        return Err(CoreError::InvalidConfig {
                            detail: format!(
                                "channel {channel:?} has a writer allow-list but \
                                 [ingest].writer_policy = \"off\", so the list is ignored and \
                                 every writer is accepted. Set writer_policy to \"warn\" or \
                                 \"enforce\" to consult the list, or remove the list."
                            ),
                        });
                    }
                }
                Ok(())
            }
            // `warn` is the discovery mode: it consults the list without failing closed.
            WriterPolicy::Warn => Ok(()),
            // `enforce` with an empty list would reject everything on that channel; require an
            // explicit acknowledgement to accept that posture.
            WriterPolicy::Enforce => {
                // `enforce` gates crypt4gh writer keys. A node with no identity can decrypt no
                // `.tar.c4gh` at all, so every artifact reaching it is a plaintext staging dir —
                // which carries no writer key and is quarantined under `enforce`. It would
                // reject 100% of its inputs, forever. Unlike an empty allow-list this is not a
                // posture but an incoherence, so `allow_any_writer_ack` does not waive it.
                if self.keys.identities.is_empty() && !self.has_vault() {
                    return Err(CoreError::InvalidConfig {
                        detail: "[ingest].writer_policy = \"enforce\" gates crypt4gh writer keys, \
                                 but this node has no [keys].identities (and no [vault]): it can \
                                 decrypt no .tar.c4gh, so every drop would be an unidentified \
                                 plaintext staging dir and be quarantined. Give the node an \
                                 identity, or use writer_policy = \"warn\" / \"off\"."
                            .to_owned(),
                    });
                }
                if !self.ingest.allow_any_writer_ack.trim().is_empty() {
                    return Ok(());
                }
                for channel in &channels {
                    if self.writer_allowlist_for(channel).is_empty() {
                        return Err(CoreError::InvalidConfig {
                            detail: format!(
                                "[ingest].writer_policy = \"enforce\" but channel {channel:?} has \
                                 an empty allow-list: it would reject every encrypted package. Add \
                                 fingerprints for it, or set [ingest].allow_any_writer_ack to a \
                                 reason to accept that posture."
                            ),
                        });
                    }
                }
                Ok(())
            }
        }
    }

    /// Whether the resolved config carries a `[vault]` block.
    ///
    /// Used by the service-side feature preflight to reject a Vault config on a
    /// binary built without the `vault` feature.
    #[must_use]
    pub fn has_vault(&self) -> bool {
        self.vault.is_some()
    }

    /// Whether the resolved config sets `[vault].transit_key` (the PME runtime
    /// switch).
    ///
    /// Used by the service-side feature preflight to reject a `transit_key` on a
    /// binary built without the `pme` feature.
    #[must_use]
    pub fn has_transit_key(&self) -> bool {
        self.vault.as_ref().is_some_and(|v| v.transit_key.is_some())
    }

    /// Validate the `[fairdp]` block (only reached when it is present).
    ///
    /// Enforces, in order:
    /// - `title`, `license`, `issued` and `language` are non-empty; `license` and
    ///   `language` are valid IRIs;
    /// - the publisher and HDAB contact points are each complete (`fn` non-empty,
    ///   `has_email` matching `^mailto:.+@.+\..+$`, `has_url` a valid URL if set);
    /// - the publisher `homepage`/`mbox`, every `theme`, and every
    ///   `applicable_legislation` entry are valid IRIs;
    /// - the theme/theme-taxonomy in-scheme rule (see
    ///   [`ServiceConfig::check_theme_scheme`]).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidConfig`] naming the offending `[fairdp]` key.
    fn preflight_fairdp(fairdp: &FairdpConfig) -> CoreResult<()> {
        check_non_empty("fairdp.title", &fairdp.title)?;
        check_non_empty("fairdp.issued", &fairdp.issued)?;
        // `issued` is emitted verbatim as a typed literal `"…"^^xsd:dateTime` on the
        // FDP-root/Catalog `metadataIssued`/`metadataModified` (and as the fallback
        // `dct:issued`/`dct:modified`). This parse only rejects a value that is not an
        // RFC-3339 instant at all; RFC-3339 is a superset of the xsd:dateTime lexical
        // space (it also admits a space separator and lowercase `t`/`z`), so a
        // parseable-but-non-canonical value is normalized into xsd:dateTime form at load
        // (see `from_figment`) — not here — before it can reach the serializer.
        if time::OffsetDateTime::parse(
            &fairdp.issued,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
        {
            return Err(invalid_config(
                "fairdp.issued must be an RFC-3339 / xsd:dateTime instant (e.g. 2024-01-01T00:00:00Z)",
            ));
        }
        check_non_empty("fairdp.license", &fairdp.license)?;
        check_iri("fairdp.license", &fairdp.license)?;

        // `language` defaults to the English authority IRI, so the only way to reach
        // here with a bad one is an explicit override — which is emitted verbatim as
        // `dct:language` on the root, every catalog and every dataset. An empty string
        // would emit `<>` (the base IRI) on all of them.
        check_non_empty("fairdp.language", &fairdp.language)?;
        check_iri("fairdp.language", &fairdp.language)?;

        // The publisher (`dct:publisher foaf:name`) and HDAB (`gdi:hasDataAuthorisation`)
        // names are mandatory in the served FDP-root/Catalog RDF; both default empty and
        // are emitted verbatim, so an empty value serves SHACL-non-conformant metadata.
        check_non_empty("fairdp.publisher.name", &fairdp.publisher.name)?;
        check_non_empty("fairdp.hdab.name", &fairdp.hdab.name)?;

        check_contact_point(
            "fairdp.publisher.contact_point",
            &fairdp.publisher.contact_point,
        )?;
        check_contact_point("fairdp.hdab.contact_point", &fairdp.hdab.contact_point)?;

        if let Some(homepage) = &fairdp.publisher.homepage {
            check_iri("fairdp.publisher.homepage", homepage)?;
        }
        if let Some(mbox) = &fairdp.publisher.mbox {
            // `foaf:mbox` is a `mailto:` IRI: validate it as an email — which pins the
            // scheme to `mailto:` — not as a generic IRI, so a `javascript:`/`data:`
            // value cannot slip through into the served RDF.
            crate::validate_pkg::validate_email("fairdp.publisher.mbox", mbox)
                .map_err(|e| invalid_config(&e.to_string()))?;
        }
        // The Catalog record carries `dcatap:applicableLegislation` (gdi-metadata
        // `CatalogShape` `sh:minCount 1`); with none configured the node would serve a
        // SHACL-non-conformant `dcat:Catalog`. Require at least one, mirroring `theme`.
        if fairdp.applicable_legislation.is_empty() {
            return Err(invalid_config(
                "fairdp.applicable_legislation must list at least one IRI (the Catalog requires dcatap:applicableLegislation)",
            ));
        }
        for legislation in &fairdp.applicable_legislation {
            check_iri("fairdp.applicable_legislation", legislation)?;
        }
        // A dataset record carries `dcat:theme` (DatasetShape `sh:minCount 1`) and
        // the Catalog `dcat:themeTaxonomy` (derived from the theme scheme); with no
        // theme configured the node would serve SHACL-non-conformant RDF. Require at
        // least one.
        if fairdp.theme.is_empty() {
            return Err(invalid_config(
                "fairdp.theme must list at least one theme IRI (datasets require dcat:theme; the Catalog requires dcat:themeTaxonomy)",
            ));
        }
        for theme in &fairdp.theme {
            check_iri("fairdp.theme", theme)?;
        }

        Self::check_theme_scheme(&fairdp.theme, fairdp.theme_taxonomy.as_deref())?;
        Ok(())
    }

    /// Validate the theme / theme-taxonomy SKOS-scheme rule.
    ///
    /// When `theme_taxonomy` is set, every `theme` must be in-scheme — that is, start with
    /// `theme_taxonomy` + `/` — or the node refuses to start. When it is unset, the scheme
    /// is derived from a theme concept IRI minus its final path segment, and all themes must
    /// share one derivable scheme. An empty
    /// `theme` list is tolerated here (a no-op), but [`ServiceConfig::preflight_fairdp`]
    /// requires at least one theme before this is reached.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidConfig`] when a theme is not in the configured
    /// taxonomy, when a theme has no derivable scheme, or when the themes do not
    /// share one scheme.
    fn check_theme_scheme(theme: &[String], theme_taxonomy: Option<&str>) -> CoreResult<()> {
        if let Some(taxonomy) = theme_taxonomy {
            let prefix = format!("{}/", taxonomy.trim_end_matches('/'));
            for t in theme {
                if !t.starts_with(&prefix) {
                    return Err(invalid_config(
                        "fairdp.theme value is not in-scheme for fairdp.theme_taxonomy",
                    ));
                }
            }
            return Ok(());
        }
        // Derive each theme's scheme (the IRI minus its final path segment) and
        // require a single shared one.
        let mut derived: Option<&str> = None;
        for t in theme {
            let Some(scheme) = derived_theme_scheme(t) else {
                return Err(invalid_config(
                    "fairdp.theme value has no derivable SKOS scheme (no parent path)",
                ));
            };
            match derived {
                None => derived = Some(scheme),
                Some(existing) if existing != scheme => {
                    return Err(invalid_config(
                        "fairdp.theme values do not share one derivable SKOS scheme; set fairdp.theme_taxonomy",
                    ));
                }
                Some(_) => {}
            }
        }
        Ok(())
    }
}

/// Build an [`CoreError::InvalidConfig`] from a static-ish detail string.
fn invalid_config(detail: &str) -> CoreError {
    CoreError::InvalidConfig {
        detail: detail.to_owned(),
    }
}

/// Require a mandatory config string to be non-empty, naming the field.
///
/// The `<field> is required` rule recurs across every validated block
/// ([`ServiceConfig::preflight`], `preflight_vault`, `preflight_fairdp`): each of those
/// fields defaults to an empty string that is still emitted verbatim into a served document,
/// so a blank value must fail at boot rather than serve a nameless record.
fn check_non_empty(field: &str, value: &str) -> CoreResult<()> {
    if value.is_empty() {
        return Err(invalid_config(&format!("{field} is required")));
    }
    Ok(())
}

/// The narrow config subset a running node can reload on `SIGHUP` without a restart:
/// `[catalogs]` and the `[ingest]` writer-key allow-list, meaning `writer_policy` and
/// every `allowed_writer_fingerprints`, both the inbox one and each `[[s3.buckets]]`'s
/// own. Everything else in [`ServiceConfig`] stays on the immutable boot
/// `Arc<ServiceConfig>` and is restart-only by construction, by not being represented
/// here: listeners, identities, `[vault]`, bucket endpoints and credentials,
/// `data_dir`, and the k-anonymity `min_allele_count` floor.
///
/// `AppState` holds this behind a small `Arc<RwLock<Arc<Reloadable>>>` cell: a reader clones
/// the inner `Arc` under a brief read lock, then reads the clone lock-free; `SIGHUP` swaps
/// the whole inner `Arc` under the write lock, so a reader racing the swap always observes a
/// complete old-or-new snapshot, never a torn mix of old catalogs with new fingerprints.
#[derive(Debug, Clone, Default)]
pub struct Reloadable {
    /// `[catalogs]`: catalog name -> display title.
    pub catalogs: BTreeMap<String, String>,
    /// `[ingest].writer_policy`.
    pub writer_policy: WriterPolicy,
    /// `[ingest].inbox_allowed_writer_fingerprints`.
    pub inbox_allowed_writer_fingerprints: Vec<String>,
    /// Every `[[s3.buckets]].allowed_writer_fingerprints`, keyed by the bucket's `name` (the
    /// channel). The key set is whatever the last boot or reload observed, so it tracks an
    /// added bucket, whose monitor the reload also starts. A channel absent here after a
    /// reload means the reloaded file no longer names that bucket, not that its list was
    /// cleared — and since bucket removal stays restart-only, that channel's monitor is still
    /// running; [`ServiceConfig::changed_outside_reloadable_subset`] flags the case.
    pub per_channel_allowed_writer_fingerprints: BTreeMap<String, Vec<String>>,
    /// Every channel this snapshot declares: each `[[s3.buckets]].name`, plus `inbox` when
    /// `[service].inbox` is set. This is where "which channels are configured" is answered.
    /// The orphan rule — a channel the status index owns datasets for but this set does not
    /// name is withheld — reads it, so a bucket a reload adds is declared from the moment the
    /// reload lands. A bucket a reload removes is carried forward by
    /// [`Self::retaining_removed_channels`], like its allow-list above: removal is
    /// restart-only, that monitor is still polling, and withholding a channel that is still
    /// reconciling would flap against its own reconcile until the restart.
    pub channels: std::collections::BTreeSet<String>,
}

impl Reloadable {
    /// Extract the reloadable subset from a freshly loaded/validated [`ServiceConfig`] —
    /// used both at `AppState` construction (the boot snapshot) and on a successful
    /// `SIGHUP` reload.
    #[must_use]
    pub fn from_config(config: &ServiceConfig) -> Self {
        let per_channel_allowed_writer_fingerprints = config
            .s3
            .as_ref()
            .map(|s3| {
                s3.buckets
                    .iter()
                    .map(|b| (b.name.clone(), b.allowed_writer_fingerprints.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let mut channels: std::collections::BTreeSet<String> = config
            .s3
            .as_ref()
            .map(|s3| s3.buckets.iter().map(|b| b.name.clone()).collect())
            .unwrap_or_default();
        if config.service.inbox.is_some() {
            channels.insert("inbox".to_owned());
        }
        Self {
            catalogs: config.catalogs.clone(),
            writer_policy: config.ingest.writer_policy,
            inbox_allowed_writer_fingerprints: config
                .ingest
                .inbox_allowed_writer_fingerprints
                .clone(),
            per_channel_allowed_writer_fingerprints,
            channels,
        }
    }

    /// Carry forward the per-channel allow-lists of channels `previous` had and this one
    /// does not — the buckets the reloaded file removed.
    ///
    /// Bucket removal is restart-only: the monitor keeps running and its datasets keep
    /// serving. Its configuration must therefore keep applying too, and the allow-list is
    /// the part with teeth. Without this, a reload that drops a `[[s3.buckets]]` entry
    /// leaves that still-running monitor with an empty allow-list, and under
    /// `writer_policy = "enforce"` an empty list admits nothing — so every package
    /// published to that bucket from then on is quarantined as `writer-rejected`, while
    /// the reload's own warning says removal "changes nothing until a restart".
    ///
    /// That outcome is fail-safe in direction but silent in operation, and contradicts what
    /// the reload told the operator, which is why the lists are carried rather than
    /// documented away.
    #[must_use]
    pub fn retaining_removed_channels(mut self, previous: &Self) -> Self {
        for (channel, allowlist) in &previous.per_channel_allowed_writer_fingerprints {
            self.per_channel_allowed_writer_fingerprints
                .entry(channel.clone())
                .or_insert_with(|| allowlist.clone());
        }
        // The same carry-forward for the channel set itself (see `channels`): a removed
        // bucket's monitor is still polling, so its datasets must not read as orphaned.
        self.channels.extend(previous.channels.iter().cloned());
        self
    }

    /// The writer-key allow-list for a channel — a bucket's `name`, or `inbox` — sourced
    /// from this reloadable snapshot rather than the boot config. Empty when the channel
    /// has no list, or is unknown to this snapshot. Mirrors
    /// [`ServiceConfig::writer_allowlist_for`]; see that method's doc for which one a
    /// caller should use.
    #[must_use]
    pub fn writer_allowlist_for(&self, channel: &str) -> &[String] {
        if channel == "inbox" {
            return &self.inbox_allowed_writer_fingerprints;
        }
        self.per_channel_allowed_writer_fingerprints
            .get(channel)
            .map_or(&[], Vec::as_slice)
    }
}

/// The `<SET ME …>` placeholder the shipped `node.quickstart.toml` carries for each
/// field an operator must fill in. A resolved config still containing it is unfinished;
/// [`ServiceConfig::preflight`] rejects it (see `preflight_no_placeholders`).
const PLACEHOLDER_SENTINEL: &str = "<SET ME";

/// Reject an unreplaced `<SET ME …>` sentinel in a field the placeholder walk cannot see.
///
/// Only needed for `#[serde(skip_serializing)]` fields — everything else is covered by
/// [`ServiceConfig::preflight`]'s leaf walk, which is the mechanism to prefer.
///
/// # Errors
///
/// Returns [`CoreError::InvalidConfig`] when `value` contains the sentinel.
fn check_no_placeholder(field: &str, value: Option<&str>) -> CoreResult<()> {
    if value.is_some_and(|v| v.contains(PLACEHOLDER_SENTINEL)) {
        return Err(invalid_config(&format!(
            "{field} still contains an unreplaced `{PLACEHOLDER_SENTINEL} ...>` placeholder; \
             set it before starting"
        )));
    }
    Ok(())
}

/// Collect the dotted paths of every JSON string leaf whose value contains
/// [`PLACEHOLDER_SENTINEL`]. Records paths only, never values, which may be secrets.
fn collect_placeholder_paths(prefix: &str, value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) if s.contains(PLACEHOLDER_SENTINEL) => {
            out.push(prefix.to_owned());
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                collect_placeholder_paths(&path, v, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                collect_placeholder_paths(&format!("{prefix}[{i}]"), v, out);
            }
        }
        _ => {}
    }
}

/// Warn when one bucket allow-lists more than one writer key — the shared-bucket posture.
///
/// A bucket is a single trust domain, not a multi-tenant surface: the per-dataset
/// `{id}.state.json` sidecar is unsigned, so any writer holding PUT access to the bucket can
/// flip any other writer's dataset between visible and hidden. `writer_policy = "enforce"`
/// does not stop it, because that recovers and allow-lists the crypt4gh writer of the
/// package, and the sidecar carries no writer identity to check.
///
/// Sidecar signing is deliberately not implemented: it would defend against an attacker who
/// already holds bucket write access and could equally delete the package or overwrite the
/// sync marker. The proportionate control is one provider per bucket with per-bucket
/// credentials, so this makes the shared-bucket shape loud rather than silent.
///
/// `None` for a single key, the intended shape, and for an empty allow-list, where the list
/// is off entirely — a separate posture governed by `writer_policy`.
#[must_use]
pub(crate) fn shared_bucket_writer_warning(channel: &str, fingerprints: usize) -> Option<String> {
    (fingerprints > 1).then(|| {
        format!(
            "channel `{channel}` allow-lists {fingerprints} writer keys, but a bucket is a \
             single trust domain. The `{{id}}.state.json` sidecar is unsigned, so any of \
             those writers can flip any other's dataset visible/hidden, and `writer_policy` \
             cannot stop it (it validates the package's writer, not the sidecar's). Prefer \
             one provider per bucket with per-bucket credentials. If these are rotation keys \
             for a single provider, this is expected."
        )
    })
}

/// Advisory for `[audit].enabled = false`: the governance trail is off.
///
/// The sibling silencing path — a log-level filter that would hide `target: "audit"` — is
/// hardened to the point of rewriting the operator's directive (`strip_audit_directives`), so
/// no level knob can erase the audit trail. This switch erases every governance event
/// outright, so a node with no audit trail would otherwise look identical at boot to one with
/// a complete trail.
///
/// A warning rather than an error: disabling the trail is a legitimate posture for a
/// throwaway development node, as `min_allele_count = 0` is. It only has to be visible.
pub(crate) fn audit_disabled_warning(enabled: bool) -> Option<&'static str> {
    (!enabled).then_some(
        "[audit].enabled is false: the governance audit trail is DISABLED, so no query, \
         ingest, retract, identity or configuration event is recorded. Note that the \
         log-level path cannot do this (audit directives are stripped from GDI_LOG \
         precisely so the trail cannot be silenced by accident), but this switch silences \
         it completely. Intended only for a throwaway development node; leave it at the \
         default `true` anywhere that answers real queries.",
    )
}

/// The startup warning to emit when node-level k-anonymity suppression is disabled
/// (`[beacon].min_allele_count == 0`), or `None` when a floor is set. Fired in every
/// environment — the aggregated plane is unauthenticated regardless of `environment`.
///
/// `[beacon].min_allele_count == 0` means the node applies no baseline small-count floor:
/// unless every dataset sets its own `config.minAlleleCount`, exact aggregate counts,
/// including singletons, are served. This is a legitimate posture for a consortium whose DPIA
/// treats aggregate allele frequencies as non-identifying, and it is the shipped default, so
/// it warns rather than failing — but the choice should be a conscious, auditable one. Fired
/// whenever the floor is 0, in every environment: the aggregated `g_variants` plane is
/// unauthenticated regardless of the `environment` string or `security_level` label, so a
/// node labelled `dev` or `staging` can still be internet-facing with suppression off.
pub(crate) fn suppression_disabled_warning(min_allele_count: u32) -> Option<&'static str> {
    (min_allele_count == 0).then_some(
        "[beacon].min_allele_count is 0: node-level k-anonymity suppression is disabled, so \
         exact aggregate counts (including singletons) are served for any dataset that does not \
         set its own config.minAlleleCount, and marginal differencing can re-identify them. The \
         aggregated g_variants plane is unauthenticated regardless of environment or \
         security_level, so this fires in every environment. This is intended only if your DPIA \
         treats aggregate allele frequencies as non-identifying; otherwise set a floor (the \
         floor counts alleles, so use about 2*k for k individuals: min_allele_count = 10 for \
         k = 5). A floor alone does not defeat all differencing: see docs/threat-model.md.",
    )
}

/// Tokio's default blocking-thread pool size (`max_blocking_threads`); the node does not
/// override it. Used only to size the advisory warning below.
const TOKIO_DEFAULT_BLOCKING_THREADS: u64 = 512;

/// Advisory warning when the Beacon read path could exhaust tokio's shared blocking-thread
/// pool. Each `POST /g_variants` fans out up to `ingest_concurrency` `spawn_blocking`
/// parquet scans, so `max_concurrent_requests * ingest_concurrency` bounds the read path's
/// peak demand on the pool that also serves ingest / PME. Over the pool size, broad-query
/// load can starve ingest (throughput degradation, not a crash). Returns the message, or
/// `None` at safe settings (the defaults 64 * 4 = 256 are well under 512).
pub(crate) fn blocking_pool_pressure_warning(
    max_concurrent_requests: usize,
    ingest_concurrency: usize,
) -> Option<String> {
    let demand = (max_concurrent_requests as u64).saturating_mul(ingest_concurrency as u64);
    (demand > TOKIO_DEFAULT_BLOCKING_THREADS).then(|| {
        format!(
            "service.max_concurrent_requests ({max_concurrent_requests}) * \
             ingest_concurrency ({ingest_concurrency}) = {demand} exceeds tokio's blocking-thread \
             pool ({TOKIO_DEFAULT_BLOCKING_THREADS}): under broad-query load the g_variants scans \
             can starve ingest/PME on the shared pool. Lower one of the two knobs."
        )
    })
}

/// The beacon-type segment values the GDI id convention admits.
const GDI_BEACON_TYPES: [&str; 2] = ["af-beacon", "sl-beacon"];

/// The environment segment the GDI id convention expects for a given
/// `[beacon].environment`, or `None` when this node is not a deployed one.
///
/// The convention admits only `staging` and `production`, while the node's `environment` enum
/// is `dev` | `test` | `staging` | `prod`, so `prod` renders as `production`. The node keeps
/// `prod`, which is coupled to `production_status`, [`is_production`] and every deployed
/// config.
///
/// `dev` and `test` map to `None`: the convention governs nodes published to the GDI User
/// Portal, and a local or CI node is not one, so there is no correct id for it to hold.
fn gdi_env_segment(environment: &str) -> Option<&'static str> {
    match environment {
        "prod" => Some("production"),
        "staging" => Some("staging"),
        _ => None,
    }
}

/// Advisory warning when `[beacon].id` departs from the GDI-harmonized convention
/// `<cc>.<institution>.<af-beacon|sl-beacon>.<staging|production>[.<extra>]`, which the
/// GDI User Portal integrates against (e.g. `es.crg.af-beacon.production.fega-spain`).
///
/// A warning and not a preflight error on purpose: the id is a naming convention, not a
/// correctness invariant, and rejecting it outright would refuse to boot every node whose id
/// predates the convention — an upgrade that bricks a running beacon is worse than a
/// non-conformant id. It is emitted from [`ServiceConfig::emit_startup_advisories`], so
/// `check-config` surfaces it on the pre-deploy path.
///
/// The second check is the one that earns its keep: the environment appears both in the id
/// and in `[beacon].environment`, so the two can drift silently (an id ending `.production`
/// on a node configured `environment = "staging"`). Checking agreement here binds them rather
/// than leaving a second hand-maintained copy of the same fact.
///
/// Deployed nodes only. `dev` and `test` are skipped entirely (see [`gdi_env_segment`]): the
/// convention exists so the GDI User Portal can find a beacon, and a local or CI node is
/// never published to it. Warning there would be noise on every local boot, and unfixable
/// noise at that, since the convention has no segment those environments could use.
///
/// Returns `None` when the node is not deployed, or when the id conforms and its
/// environment segment agrees.
pub(crate) fn beacon_id_convention_warning(id: &str, environment: &str) -> Option<String> {
    const SHAPE: &str = "<cc>.<institution>.<af-beacon|sl-beacon>.<staging|production>[.<extra>]";
    // Not a deployed node, so the convention does not apply. Skip before inspecting the id.
    let expected_env = gdi_env_segment(environment)?;
    let parts: Vec<&str> = id.split('.').collect();
    let well_formed = parts.len() >= 4
        && parts[0].len() == 2
        && parts[0].bytes().all(|b| b.is_ascii_lowercase())
        && !parts[1].is_empty()
        && parts[1]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && GDI_BEACON_TYPES.contains(&parts[2])
        && matches!(parts[3], "staging" | "production");
    if !well_formed {
        return Some(format!(
            "[beacon].id {id:?} does not follow the GDI-harmonized beacon-id convention \
             {SHAPE} (e.g. \"es.crg.af-beacon.production.fega-spain\"). The GDI User Portal \
             integrates against this form, so a non-conformant id can fail to be picked up. \
             This node serves aggregated allele frequencies, so the type segment is \
             `af-beacon`."
        ));
    }
    // Conformant and in step — nothing to say.
    if parts[3] == expected_env {
        return None;
    }
    Some(format!(
        "[beacon].id {id:?} declares environment {:?} but [beacon].environment is \
         {environment:?} (which the convention spells {expected_env:?}). The two are the same \
         fact in two places; fix whichever is wrong before the id is published to the GDI \
         User Portal.",
        parts[3]
    ))
}

/// Whether `url_str`'s host is a loopback address (`127.0.0.0/8`, `::1`) or the literal
/// `localhost` — the case where plaintext HTTP is not a real man-in-the-middle exposure, such
/// as a same-host development or sidecar backend. Used to exempt loopback endpoints from the
/// production plaintext-transport preflight for Vault and for S3. A URL that does not parse
/// is treated as non-loopback.
fn host_is_loopback(url_str: &str) -> bool {
    let Ok(url) = url::Url::parse(url_str) else {
        return false;
    };
    match url.host() {
        Some(url::Host::Domain(h)) => h.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Validate an `[[s3.buckets]].prefix` (empty ⇒ the whole bucket, always accepted).
///
/// The rule is narrower than what S3 permits in a key: one or more
/// slash-separated segments of ASCII letters, digits, `-`, `_` or `.`, with an optional
/// trailing `/`, and no segment that is `.` or `..`. The prefix must reach the wire
/// unchanged, and only that character set does — the two ways it would not:
///
/// * `object_store::path::Path` percent-encodes the characters AWS and GCS recommend
///   avoiding (backslash, backtick, CR/LF, controls and `{ ^ } % ] " > [ ~ < # | * ?`) and
///   rewrites a `.`/`..` segment to `%2E`/`%2E%2E`. A prefix with one addresses `a%23b/` on
///   the wire while the operator, the bucket policy and every other writer say `a#b/` — a
///   channel that lists nothing, with a correct-looking config.
/// * A leading `/`, an empty segment (`//`) or a `.`/`..` segment is silently collapsed
///   by that same normalization, so the node would quietly monitor a different prefix
///   than the one a prefix-scoped credential grants.
///
/// Both failures present identically at runtime — an empty listing on a healthy-looking
/// channel — which is why this is a boot rejection rather than a warning.
fn validate_bucket_prefix(channel: &str, prefix: &str) -> CoreResult<()> {
    validate_key_prefix(prefix).map_err(|why| CoreError::InvalidConfig {
        detail: format!(
            "s3 channel {channel:?} has an invalid prefix {prefix:?}: {why}. Use \
             slash-separated segments of letters, digits, '-', '_' or '.' (e.g. \
             \"gdi-node-storage/\"), which is what the bucket policy and every other \
             writer address"
        ),
    })
}

/// The prefix rule itself, shared by the reader and the writer. Returns why a prefix is
/// unusable, or `Ok(())`.
///
/// Public and context-free on purpose. The node rejects a bad prefix at boot, through the
/// private `validate_bucket_prefix` which wraps this with the bucket name, and
/// `gdi-dataset-tool` must reject the same spellings before it writes, because the two
/// address one keyspace and a prefix the writer silently rewrites is an upload the node never
/// lists. A second copy of this rule in the tool would drift from this one, and the symptom
/// of the drift is the desync it exists to prevent.
///
/// # Errors
///
/// Returns the reason the prefix would not reach the wire unchanged. Empty is always `Ok`
/// (the whole bucket).
pub fn validate_key_prefix(prefix: &str) -> Result<(), String> {
    if prefix.is_empty() {
        return Ok(());
    }
    if prefix.starts_with('/') {
        return Err("it must not start with '/' (S3 keys have no leading slash)".to_owned());
    }
    // Exactly one optional trailing '/' is the conventional way to write a prefix and carries
    // no information either way, so it is accepted here and normalized away by the store
    // wrapper.
    //
    // `strip_suffix`, not `trim_end_matches`: the latter strips a run of them, which would let
    // `"a//"` through while it normalizes to `a/` on the wire — the silent renormalization
    // this function exists to reject, and inconsistent with `a//b` being refused for the same
    // reason.
    let body = prefix.strip_suffix('/').unwrap_or(prefix);
    for segment in body.split('/') {
        if segment.is_empty() {
            return Err("it has an empty segment ('//')".to_owned());
        }
        if segment == "." || segment == ".." {
            return Err("'.' and '..' are not usable as key segments".to_owned());
        }
        if let Some(bad) = segment
            .chars()
            .find(|c| !c.is_ascii_alphanumeric() && !matches!(c, '-' | '_' | '.'))
        {
            return Err(format!("{bad:?} is not allowed in a prefix"));
        }
    }
    Ok(())
}

/// Whether this node is a production deployment for the purpose of plaintext-transport
/// warnings: `beacon.environment == "prod"`, or the advertised `production_status == "PROD"`.
///
/// Gating on both — the same predicate `preflight_vault` uses — closes the gap where an env
/// overlay flips the single `environment` string to `dev` to suppress a warning while the
/// node still advertises `PROD` to clients. A genuine non-production node sets both
/// `environment` to dev/test/staging and `production_status` away from `PROD`, which it must
/// already do to pass the Vault check, so this adds no burden and only closes the downgrade.
fn is_production(environment: &str, production_status: &str) -> bool {
    environment == "prod" || production_status == "PROD"
}

/// Validate that `value` is an absolute IRI/URL fit to serve verbatim in the FDP
/// RDF: an allowed URI scheme, which rejects `javascript:`, `data:` and `file:`,
/// no `IRIREF`-forbidden character, a host or opaque path, and within the IRI length
/// cap. Delegates to the package validator ([`crate::validate_pkg::validate_iri`]) and
/// re-wraps its error as a config error, so the config and package IRI checks can
/// never drift on these security-critical rules — in particular the scheme allow-list,
/// which both paths must apply.
fn check_iri(field: &str, value: &str) -> CoreResult<()> {
    crate::validate_pkg::validate_iri(field, value).map_err(|e| invalid_config(&e.to_string()))
}

/// Validate an optional `/info` link (`documentationUrl`, `alternativeUrl`, `welcomeUrl`,
/// `contactUrl`, `logoUrl`): an absolute `http`/`https` URL, or — for `contactUrl` only,
/// `allow_mailto` — a well-formed `mailto:` address (the same rule `has_email`/`mbox` pass,
/// checked here on a lowercase-prefixed copy). The scheme itself is matched
/// case-insensitively (RFC 3986 §3.1); `is_mailto_email` stays lowercase-only because the
/// FDP fields that share it are checked against SHACL shapes whose `^mailto:` pattern is
/// case-sensitive — this `/info` link is not RDF, so it normalises here instead.
/// Same reason as the `base_url` scheme check above it: these are served verbatim to
/// whatever renders `/info` as links, so `javascript:`/`data:`/`file:` must not reach it.
/// Kept apart from [`check_iri`] on purpose: that is the RDF IRI rule (it admits `urn:` and
/// `doi:`, which are not links a browser follows).
fn check_info_url(field: &str, value: &str, allow_mailto: bool) -> CoreResult<()> {
    if let Some((scheme, rest)) = value.split_at_checked(7)
        && scheme.eq_ignore_ascii_case("mailto:")
    {
        if !allow_mailto {
            return Err(invalid_config(&format!(
                "{field} scheme \"mailto\" is not allowed (expected http or https); it is served \
                 as a link in /info"
            )));
        }
        if crate::validate_pkg::is_mailto_email(&format!("mailto:{rest}")) {
            return Ok(());
        }
        return Err(invalid_config(&format!(
            "{field} is not a well-formed mailto: address (expected mailto:user@host.tld)"
        )));
    }
    let Ok(parsed) = url::Url::parse(value) else {
        return Err(invalid_config(&format!("{field} is not a valid URL")));
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(invalid_config(&format!(
            "{field} scheme {:?} is not allowed (expected http or https{}); it is served as a \
             link in /info",
            parsed.scheme(),
            if allow_mailto { " or mailto" } else { "" }
        )));
    }
    Ok(())
}

/// The SKOS `ConceptScheme` a `dcat:theme` concept IRI belongs to: the IRI minus its
/// final `/`-separated segment, or [`None`] when there is no non-empty parent path (an
/// opaque IRI such as a `urn:`). Single-sources the derivation shared by
/// [`FairdpConfig::theme_taxonomy_iri`] and [`ServiceConfig::check_theme_scheme`] — they
/// must agree, since preflight validates the themes against the very scheme the renderer
/// later derives from them.
fn derived_theme_scheme(theme: &str) -> Option<&str> {
    // Trim a trailing `/` first. IRIs are commonly written with one, and without this
    // `…/scheme/concept/` splits into (`…/scheme/concept`, ``) — so the "parent path" is
    // the concept itself and `dcat:themeTaxonomy` is published pointing at a concept
    // rather than the ConceptScheme that contains it. Silent: the IRI is well-formed and
    // resolves, it is one level too deep, so a harvester reads the wrong scheme.
    theme
        .strip_suffix('/')
        .unwrap_or(theme)
        .rsplit_once('/')
        .map(|(head, _)| head)
        .filter(|head| !head.is_empty())
}

/// Validate a contact point: `fn` non-empty, `has_email` matching the mailto
/// pattern, `has_url` a valid URL when present.
fn check_contact_point(field: &str, cp: &ContactPointCfg) -> CoreResult<()> {
    if cp.fn_.is_empty() {
        return Err(invalid_config(&format!("{field}.fn is required")));
    }
    if cp.has_email.is_empty() {
        return Err(invalid_config(&format!("{field}.has_email is required")));
    }
    // The pattern and the cap both come from `validate_pkg`, which owns this rule for
    // package fields and which the IRI-character check below also calls into. A local copy
    // here would drop the cap and need a static-regex `expect` waiver.
    if cp.has_email.chars().count() > crate::validate_pkg::MAX_EMAIL_LEN {
        return Err(invalid_config(&format!(
            "{field}.has_email exceeds the {}-char limit",
            crate::validate_pkg::MAX_EMAIL_LEN
        )));
    }
    if !crate::validate_pkg::is_mailto_email(&cp.has_email) {
        return Err(invalid_config(&format!(
            "{field}.has_email is not a mailto: email"
        )));
    }
    // The mailto and contact URL are both emitted verbatim as `<…>` IRIs, so guard both
    // against IRIREF-forbidden characters.
    if let Some(c) = crate::validate_pkg::find_iri_unsafe_char(&cp.has_email) {
        return Err(invalid_config(&format!(
            "{field}.has_email contains a character not allowed in an IRI ({c:?})"
        )));
    }
    if let Some(url) = &cp.has_url {
        // `vcard:hasURL` is emitted verbatim as an IRI, so it gets the same scheme
        // allow-list and IRIREF-char rejection as any other served IRI.
        check_iri(&format!("{field}.has_url"), url)?;
    }
    Ok(())
}
