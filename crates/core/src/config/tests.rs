#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
#![expect(
    clippy::result_large_err,
    reason = "the figment::Jail::expect_with closure return type is fixed by the test API"
)]
use std::path::{Path, PathBuf};

use serial_test::serial;

use super::*;

/// Feeding a binary the other binary's config must say so, not emit a stray-key error.
///
/// The two schemas are disjoint, so `deny_unknown_fields` alone reports `unknown field:
/// found 'beacon', expected one of country_code/...` and leaves the operator to work out
/// that they handed the tool the node's file. The files do not share a default name, but an
/// explicit `--config` can point anywhere.
#[test]
fn tool_config_load_detects_a_service_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.toml");
    std::fs::write(
        &path,
        "[service]\nbase_url = \"http://x\"\n[beacon]\nid = \"b\"\n",
    )
    .unwrap();

    let err =
        ToolConfig::load(Some(&path)).expect_err("a service config must not load as a tool config");
    let msg = err.to_string();
    assert!(
        msg.contains("looks like a gdi-node-standalone config"),
        "must name the binary that owns this file: {msg}"
    );
    assert!(
        msg.contains("service") && msg.contains("beacon"),
        "must show the signature keys it found: {msg}"
    );
}

/// The symmetric direction: the service pointed at the provider tool's config.
#[test]
fn service_config_load_detects_a_tool_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tool.toml");
    std::fs::write(
        &path,
        "country_code = \"EE\"\ndefault_profile = \"local\"\n[profiles.local]\nservice_url = \"http://x\"\n",
    )
    .unwrap();

    let err = ServiceConfig::load(Some(&path))
        .expect_err("a tool config must not load as a service config");
    let msg = err.to_string();
    assert!(
        msg.contains("looks like a gdi-dataset-tool config"),
        "must name the binary that owns this file: {msg}"
    );
    assert!(
        msg.contains("country_code"),
        "must show the signature keys it found: {msg}"
    );
}

/// The detector must stay quiet on a valid config: a false positive would replace a real
/// parse error with a bogus "wrong binary" claim.
#[test]
fn cross_config_hint_is_silent_on_a_valid_config_of_the_expected_kind() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tool.toml");
    std::fs::write(&path, "country_code = \"EE\"\n").unwrap();
    assert!(
        cross_config_hint(&path, ConfigKind::Tool).is_none(),
        "a genuine tool config must not be reported as a service config"
    );
    // And a file carrying neither signature is ambiguous — no claim either way.
    let empty = dir.path().join("empty.toml");
    std::fs::write(&empty, "# nothing\n").unwrap();
    assert!(cross_config_hint(&empty, ConfigKind::Tool).is_none());
    assert!(cross_config_hint(&empty, ConfigKind::Service).is_none());
}

/// Shared expectation for the `preflight`-parametrized test cases below: either the
/// config must preflight cleanly, or it must fail with `InvalidConfig` naming a
/// substring of the message (an empty needle only pins the error class, for cases
/// that predate a specific message assertion).
enum Expect {
    Pass,
    Fail(&'static str),
}

/// Shared dispatch for a single `(label, toml, expect)` preflight case: parses
/// `toml`, then asserts the outcome named by `expect`.
fn assert_preflight_case(label: &str, toml: &str, expect: &Expect) {
    let cfg = ServiceConfig::from_toml_str(toml)
        .unwrap_or_else(|e| panic!("case {label}: config must parse: {e}"));
    match expect {
        Expect::Pass => cfg
            .preflight()
            .unwrap_or_else(|e| panic!("case {label}: must preflight: {e}")),
        Expect::Fail(needle) => {
            let err = cfg.preflight().unwrap_err();
            assert_eq!(
                err.class(),
                crate::error::ErrorClass::InvalidConfig,
                "case {label}"
            );
            if !needle.is_empty() {
                assert!(
                    err.to_string().contains(needle),
                    "case {label}: error should name {needle}: {err}"
                );
            }
        }
    }
}

#[test]
#[serial(env)]
fn loads_toml_and_resolves_catalogs() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "tool.toml",
            r#"
                country_code = "EE"

                [profiles.default.catalogs]
                gdi-aggregated = "Genome of Europe Aggregated Data"
                "#,
        )?;
        let cfg = ToolConfig::load(Some(Path::new("tool.toml"))).unwrap();
        assert_eq!(cfg.country_code.as_deref(), Some("EE"));
        assert_eq!(
            cfg.profiles
                .get("default")
                .and_then(|p| p.catalogs.get("gdi-aggregated"))
                .map(String::as_str),
            Some("Genome of Europe Aggregated Data")
        );
        Ok(())
    });
}

#[test]
#[serial(env)]
fn loads_named_profiles_and_default_profile() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "tool.toml",
            r#"
                default_profile = "prod"

                [profiles.prod]
                service_url = "https://gdi-ee.example.org"

                [profiles.dev]
                service_url = "http://localhost:8080"
                "#,
        )?;
        let cfg = ToolConfig::load(Some(Path::new("tool.toml"))).unwrap();
        assert_eq!(cfg.default_profile.as_deref(), Some("prod"));
        assert_eq!(cfg.profiles.len(), 2);
        assert_eq!(
            cfg.profiles
                .get("prod")
                .and_then(|p| p.service_url.as_deref()),
            Some("https://gdi-ee.example.org")
        );
        assert_eq!(
            cfg.profiles
                .get("dev")
                .and_then(|p| p.service_url.as_deref()),
            Some("http://localhost:8080")
        );
        Ok(())
    });
}

#[test]
#[serial(env)]
fn profile_header_policy_parses_the_three_profile_values() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "tool.toml",
            r#"
                [profiles.ids]
                header_policy = "with-identifiers"

                [profiles.min]
                header_policy = "minimal"

                [profiles.bare]
                header_policy = "none"

                [profiles.unset]
                service_url = "http://localhost:8080"
                "#,
        )?;
        let cfg = ToolConfig::load(Some(Path::new("tool.toml"))).unwrap();
        let policy = |name: &str| cfg.profiles.get(name).and_then(|p| p.header_policy);
        assert_eq!(policy("ids"), Some(ProfileHeaderPolicy::WithIdentifiers));
        assert_eq!(policy("min"), Some(ProfileHeaderPolicy::Minimal));
        assert_eq!(policy("bare"), Some(ProfileHeaderPolicy::None));
        assert_eq!(policy("unset"), None);
        Ok(())
    });
}

#[test]
#[serial(env)]
fn profile_header_policy_cannot_be_verbatim() {
    // `verbatim` ships tool command lines and filesystem paths: it stays a
    // per-invocation `--header-policy verbatim`, never a standing profile default.
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "tool.toml",
            r#"
                [profiles.prod]
                header_policy = "verbatim"
                "#,
        )?;
        let err = ToolConfig::load(Some(Path::new("tool.toml")))
            .expect_err("verbatim must not be a profile default");
        assert!(err.to_string().contains("verbatim"), "{err}");
        Ok(())
    });
}

#[test]
fn profile_header_policy_maps_onto_the_wire_policy() {
    use crate::model::HeaderPolicy;
    assert_eq!(
        HeaderPolicy::from(ProfileHeaderPolicy::None),
        HeaderPolicy::None
    );
    assert_eq!(
        HeaderPolicy::from(ProfileHeaderPolicy::Minimal),
        HeaderPolicy::Minimal
    );
    assert_eq!(
        HeaderPolicy::from(ProfileHeaderPolicy::WithIdentifiers),
        HeaderPolicy::WithIdentifiers
    );
}

/// `org` is an optional profile key, written by `wizard setup` and reachable through the
/// same `GDI_TOOL__PROFILES__<NAME>__…` overlay as every other profile key.
#[test]
#[serial(env)]
fn profile_org_parses_and_takes_the_env_overlay() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "tool.toml",
            r#"
                [profiles.ee]
                org = "UTARTU"

                [profiles.unset]
                service_url = "http://localhost:8080"
                "#,
        )?;
        let cfg = ToolConfig::load(Some(Path::new("tool.toml"))).unwrap();
        assert_eq!(cfg.profiles["ee"].org.as_deref(), Some("UTARTU"));
        assert_eq!(cfg.profiles["unset"].org, None);
        jail.set_env("GDI_TOOL__PROFILES__EE__ORG", "TARTU");
        let cfg = ToolConfig::load(Some(Path::new("tool.toml"))).unwrap();
        assert_eq!(cfg.profiles["ee"].org.as_deref(), Some("TARTU"));
        Ok(())
    });
}

#[test]
fn profile_node_state_base_prefers_management_url() {
    // The management-plane state base resolves: management_url wins, else
    // service_url (back-compat / shared-address), else None.
    let mut p = Profile::default();
    assert_eq!(p.node_state_base(), None);
    p.service_url = Some("http://node:8080".to_owned());
    assert_eq!(p.node_state_base(), Some("http://node:8080"));
    p.management_url = Some("http://node:9090".to_owned());
    assert_eq!(p.node_state_base(), Some("http://node:9090"));
}

#[test]
fn profile_parses_management_url() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "tool.toml",
            r#"
                [profiles.prod]
                service_url = "https://gdi-ee.example.org"
                management_url = "http://localhost:9090"
                "#,
        )?;
        let cfg = ToolConfig::load(Some(Path::new("tool.toml"))).unwrap();
        assert_eq!(
            cfg.profiles
                .get("prod")
                .and_then(|p| p.management_url.as_deref()),
            Some("http://localhost:9090")
        );
        Ok(())
    });
}

#[test]
#[serial(env)]
fn env_populates_nested_profile_and_default_profile() {
    figment::Jail::expect_with(|jail| {
        // No file: env alone populates the nested `profiles.dev.service_url`
        // map and the `tool.default_profile`.
        jail.set_env(
            "GDI_TOOL__PROFILES__DEV__SERVICE_URL",
            "http://env.example:8080",
        );
        jail.set_env("GDI_TOOL__DEFAULT_PROFILE", "dev");
        let cfg = ToolConfig::load(None).unwrap();
        assert_eq!(cfg.default_profile.as_deref(), Some("dev"));
        assert_eq!(
            cfg.profiles
                .get("dev")
                .and_then(|p| p.service_url.as_deref()),
            Some("http://env.example:8080")
        );
        Ok(())
    });
}

#[test]
#[serial(env)]
fn keys_identities_default_empty_and_parse() {
    figment::Jail::expect_with(|jail| {
        // No [keys] -> empty identities (the caller applies the implicit default).
        jail.create_file("empty.toml", "")?;
        let cfg = ToolConfig::load(Some(Path::new("empty.toml"))).unwrap();
        assert!(cfg.keys.identities.is_empty());

        // An explicit [keys].identities list parses in order.
        jail.create_file(
            "keys.toml",
            r#"
                [keys]
                identities = ["keys/provider.c4gh", "keys/provider-prev.c4gh"]
                "#,
        )?;
        let cfg = ToolConfig::load(Some(Path::new("keys.toml"))).unwrap();
        assert_eq!(
            cfg.keys.identities,
            vec![
                PathBuf::from("keys/provider.c4gh"),
                PathBuf::from("keys/provider-prev.c4gh"),
            ]
        );
        Ok(())
    });
}

#[test]
#[serial(env)]
fn env_overrides_file_for_country_code() {
    // Each layer's value is named once and the contrast is asserted, not just commented: if
    // the two literals were equal this test would pass whichever layer won. A comment cannot
    // fail; `assert_ne!` can.
    const FILE_CC: &str = "SE";
    const ENV_CC: &str = "EE";
    assert_ne!(
        FILE_CC, ENV_CC,
        "the file and env layers must carry DIFFERENT values, or this test cannot tell \
         env-wins from file-wins"
    );
    figment::Jail::expect_with(|jail| {
        jail.create_file("tool.toml", &format!("country_code = \"{FILE_CC}\"\n"))?;
        jail.set_env("GDI_TOOL__COUNTRY_CODE", ENV_CC);
        let cfg = ToolConfig::load(Some(Path::new("tool.toml"))).unwrap();
        // Env wins over the file.
        assert_eq!(cfg.country_code.as_deref(), Some(ENV_CC));
        Ok(())
    });
}

#[test]
fn flag_wins_over_config_and_env() {
    // See `env_overrides_file_for_country_code`: the contrast is asserted, not commented.
    // With both literals equal this would pass even if `resolve_country_code` ignored the
    // flag argument entirely.
    const CONFIG_CC: &str = "EE";
    const FLAG_CC: &str = "SE";
    assert_ne!(
        CONFIG_CC, FLAG_CC,
        "the flag and the configured value must DIFFER, or the flag's precedence is \
         unfalsifiable"
    );
    let cfg = ToolConfig {
        country_code: Some(CONFIG_CC.to_owned()),
        ..Default::default()
    };
    // Flag overrides the (config<env) resolved value.
    assert_eq!(
        cfg.resolve_country_code(Some(FLAG_CC)).as_deref(),
        Some(FLAG_CC)
    );
    // Without a flag, the config/env value is used — and it is not the flag's value.
    assert_eq!(cfg.resolve_country_code(None).as_deref(), Some(CONFIG_CC));
}

#[test]
#[serial(env)]
fn missing_file_loads_empty() {
    figment::Jail::expect_with(|_jail| {
        // A path that does not exist -> empty config (no error).
        let cfg = ToolConfig::load(Some(Path::new("does-not-exist.toml"))).unwrap();
        assert!(cfg.country_code.is_none());
        assert!(cfg.profiles.is_empty());
        assert!(cfg.keys.identities.is_empty());
        Ok(())
    });
}

#[test]
fn no_country_code_resolves_to_none() {
    let cfg = ToolConfig::default();
    assert!(cfg.resolve_country_code(None).is_none());
}

/// A representative service config covering the relevant blocks. The
/// `base_url` carries a trailing slash to exercise load-time stripping.
const SERVICE_TOML: &str = r#"
[service]
listen = "0.0.0.0:8080"
base_url = "https://gdi-ee.example.org/"
data_dir = "/var/lib/gdi-node-standalone/datasets"
inbox = "/var/lib/gdi-node-standalone/inbox"
ingest_concurrency = 4
rescan_interval_seconds = 300
management_addr = "0.0.0.0:9090"

[catalogs]
synthetic-data = "Synthetic Data"
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"
environment = "prod"
max_query_span_bp = 5000000

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"

[beacon.configuration]
default_granularity = "record"
production_status = "PROD"
security_level = "PUBLIC"

[fairdp]
title = "GDI Estonia FAIR Data Point"
description = "Aggregated genomic metadata for the GDI Estonia node"
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
"#;

#[test]
#[serial(env)]
fn service_config_loads_with_defaults_and_strips_base_url_slash() {
    let cfg = ServiceConfig::from_toml_str(SERVICE_TOML).unwrap();

    // Explicit values.
    assert_eq!(cfg.service.listen, "0.0.0.0:8080");
    // Trailing slash stripped on load.
    assert_eq!(cfg.service.base_url, "https://gdi-ee.example.org");
    assert_eq!(
        cfg.service.data_dir,
        PathBuf::from("/var/lib/gdi-node-standalone/datasets")
    );
    assert_eq!(
        cfg.service.inbox,
        Some(PathBuf::from("/var/lib/gdi-node-standalone/inbox"))
    );
    assert_eq!(cfg.service.ingest_concurrency, 4);
    assert_eq!(cfg.service.rescan_interval_seconds, 300);
    assert_eq!(cfg.service.management_addr, "0.0.0.0:9090");

    // Defaults applied for omitted [service] fields.
    assert_eq!(cfg.service.max_request_body_bytes, 262_144);
    assert_eq!(cfg.service.request_timeout_seconds, 30);
    assert_eq!(cfg.service.shutdown_drain_seconds, 30);
    assert_eq!(cfg.service.startup_reconcile_timeout_seconds, 30);
    assert_eq!(cfg.service.max_concurrent_requests, 64);
    assert_eq!(cfg.service.max_parquet_file_bytes, 1_073_741_824);
    assert_eq!(cfg.service.max_parquet_decompressed_bytes, 4_294_967_296);
    assert_eq!(cfg.service.max_parquet_row_group_bytes, 268_435_456);
    assert_eq!(cfg.service.rejected_retention_hours, 168);
    // Fail-closed by default: a group/other-readable identity key refuses boot.
    assert!(cfg.service.strict_key_perms);

    // Catalogs.
    assert_eq!(cfg.catalogs.len(), 2);
    assert_eq!(
        cfg.catalogs.get("gdi-aggregated").map(String::as_str),
        Some("Genome of Europe Aggregated Data")
    );

    // Beacon explicit + default values.
    assert_eq!(cfg.beacon.id, "ee.ut.af-beacon.production");
    assert_eq!(cfg.beacon.name, "GDI Estonia Beacon");
    assert_eq!(cfg.beacon.environment, "prod");
    assert_eq!(cfg.beacon.max_query_span_bp, 5_000_000);
    assert_eq!(cfg.beacon.aggregated_base_path, "/aggregated/beacon/v2");
    assert_eq!(cfg.beacon.sensitive_base_path, "/sensitive/beacon/v2");
    assert_eq!(cfg.beacon.api_version, "v2.2.0");
    assert_eq!(cfg.beacon.default_page_limit, 10);
    assert_eq!(cfg.beacon.max_page_limit, 1000);
    assert_eq!(cfg.beacon.organization.id, "ee.ut.gdi");
    assert_eq!(cfg.beacon.configuration.default_granularity, "record");

    // FDP block parses fully.
    let fairdp = cfg.fairdp.as_ref().expect("[fairdp] present");
    assert_eq!(fairdp.title, "GDI Estonia FAIR Data Point");
    assert_eq!(fairdp.issued, "2026-01-01T00:00:00Z");
    assert_eq!(
        fairdp.license,
        "https://creativecommons.org/licenses/by/4.0/"
    );
    assert_eq!(fairdp.theme.len(), 1);
    assert_eq!(fairdp.applicable_legislation.len(), 1);
    assert_eq!(fairdp.publisher.name, "University of Tartu");
    assert_eq!(
        fairdp.publisher.homepage.as_deref(),
        Some("https://gdi.ut.ee")
    );
    assert_eq!(fairdp.publisher.contact_point.fn_, "GDI Estonia");
    assert_eq!(
        fairdp.publisher.contact_point.has_email,
        "mailto:gdi@example.org"
    );
    // Distinct from `publisher.homepage` above — these are different predicates
    // (`vcard:hasURL` vs `foaf:homepage`) and the fixture must keep them apart, or a
    // renderer emitting one where the other belongs passes every assertion.
    assert_eq!(
        fairdp.publisher.contact_point.has_url.as_deref(),
        Some("https://gdi.ut.ee/contact")
    );
    assert_ne!(
        fairdp.publisher.contact_point.has_url, fairdp.publisher.homepage,
        "the contact URL and the publisher homepage must not collapse to one IRI"
    );
    assert_eq!(fairdp.hdab.name, "Estonian HDAB");
    assert_eq!(fairdp.hdab.contact_point.fn_, "Estonian HDAB");
    assert_eq!(
        fairdp.hdab.contact_point.has_email,
        "mailto:hdab@example.org"
    );

    // The representative config passes preflight.
    cfg.preflight().unwrap();
}

#[test]
#[serial(env)]
fn beacon_min_allele_count_suppression_is_off_by_default() {
    // The aggregated-beacon small-count suppression floor defaults to 0, so suppression is
    // off unless the operator opts in. A silent flip of this default would change the
    // disclosure posture of every deployment, so pin it.
    assert_eq!(
        BeaconConfig::default().min_allele_count,
        0,
        "min_allele_count must default to 0 (suppression off)"
    );

    // A parsed config whose [beacon] block omits the field inherits the same
    // default (SERVICE_TOML does not set min_allele_count).
    let cfg = ServiceConfig::from_toml_str(SERVICE_TOML).unwrap();
    assert_eq!(
        cfg.beacon.min_allele_count, 0,
        "an omitted [beacon].min_allele_count parses to the default 0"
    );
}

#[test]
fn suppression_disabled_warning_fires_whenever_floor_off() {
    // Node-level suppression off (floor 0) warns in every environment: the aggregated
    // g_variants plane is unauthenticated regardless of the environment / security_level
    // label, so a silent disclosure default must be a conscious, auditable choice. A set
    // floor does not warn.
    assert!(
        suppression_disabled_warning(0).is_some(),
        "floor 0 must warn (in any environment)"
    );
    assert!(
        suppression_disabled_warning(5).is_none(),
        "a set floor must not warn"
    );
    // The message names the field and stays honest that a floor is not a complete fix.
    let msg = suppression_disabled_warning(0).unwrap();
    assert!(
        msg.contains("min_allele_count"),
        "warning must name the field: {msg}"
    );
}

#[test]
fn shared_bucket_writer_warning_fires_only_for_more_than_one_allow_listed_key() {
    // A bucket is a single trust domain: the `{id}.state.json` sidecar is unsigned, so any
    // writer with PUT access can flip any other writer's dataset visible/hidden — including
    // under `writer_policy = "enforce"`, which validates the package's writer and not the
    // sidecar's. Two allow-listed keys on one bucket is the shape where that bites.
    assert!(
        shared_bucket_writer_warning("public", 2).is_some(),
        "two allow-listed writer keys on one bucket must warn"
    );
    assert!(
        shared_bucket_writer_warning("public", 1).is_none(),
        "a single writer key is the intended one-provider-per-bucket shape"
    );
    // Zero means the allow-list is off entirely — a different posture (covered by
    // `writer_policy`), not a shared-bucket warning.
    assert!(
        shared_bucket_writer_warning("public", 0).is_none(),
        "an empty allow-list must not raise a shared-bucket warning"
    );
    let msg = shared_bucket_writer_warning("public", 3).unwrap();
    assert!(
        msg.contains("public"),
        "warning must name the bucket so an operator can act on it: {msg}"
    );
}

#[test]
fn beacon_id_convention_warning_accepts_the_gdi_form() {
    use super::service::beacon_id_convention_warning;
    // The shipped example, and the GDI-supplied example with a trailing extra segment.
    assert!(
        beacon_id_convention_warning("ee.ut.af-beacon.production", "prod").is_none(),
        "the shipped example id must not warn"
    );
    assert!(
        beacon_id_convention_warning("es.crg.af-beacon.production.fega-spain", "prod").is_none(),
        "the optional trailing segment is allowed"
    );
    // Subject-level beacons and staging are equally conformant.
    assert!(beacon_id_convention_warning("ee.ut.sl-beacon.staging", "staging").is_none());
}

#[test]
fn beacon_id_convention_warning_flags_non_conformant_shapes() {
    use super::service::beacon_id_convention_warning;
    for id in [
        "ee.ut.gdi.beacon",            // the pre-convention reverse-DNS form
        "org.test.beacon",             // no country / type / environment
        "ee.ut.af-beacon",             // environment segment missing
        "ee.ut.beacon.production",     // type segment is not af-/sl-beacon
        "eee.ut.af-beacon.production", // 3-letter country code
        "EE.ut.af-beacon.production",  // uppercase country code
        "ee.ut.af-beacon.prod",        // node spelling, not the convention's
    ] {
        assert!(
            beacon_id_convention_warning(id, "prod").is_some(),
            "{id} must warn as non-conformant"
        );
    }
}

#[test]
fn beacon_id_convention_warning_catches_environment_drift() {
    use super::service::beacon_id_convention_warning;
    // The id and [beacon].environment are the same fact in two places. A conformant id
    // that disagrees with the configured environment is exactly the silent drift the
    // advisory exists to catch.
    let msg = beacon_id_convention_warning("ee.ut.af-beacon.production", "staging")
        .expect("production id on a staging node must warn");
    assert!(
        msg.contains("staging") && msg.contains("production"),
        "the drift warning must name both spellings: {msg}"
    );
    // `prod` renders as `production`: the node keeps its own enum spelling, so this agrees.
    assert!(beacon_id_convention_warning("ee.ut.af-beacon.production", "prod").is_none());
}

#[test]
fn beacon_id_convention_warning_skips_non_deployed_environments() {
    use super::service::beacon_id_convention_warning;
    // The convention governs nodes published to the GDI User Portal. A `dev`/`test` node is
    // never published, and the convention has no environment segment such a node could use,
    // so it is skipped entirely rather than warned about. Otherwise the shipped local stack
    // (compose/node.*.toml, all `environment = "dev"`) would emit an unfixable advisory on
    // every `docker compose up`.
    for env in ["dev", "test"] {
        for id in [
            "org.local.beacon",           // what compose/node.*.toml ships
            "org.test.beacon",            // the generic test-fixture id
            "ee.ut.af-beacon.production", // even a conformant-but-mismatched id stays quiet
        ] {
            assert!(
                beacon_id_convention_warning(id, env).is_none(),
                "environment {env:?} is not deployed: {id} must not warn"
            );
        }
    }
    // The deployed environments are still checked — the skip must not swallow them.
    for env in ["staging", "prod"] {
        assert!(
            beacon_id_convention_warning("org.local.beacon", env).is_some(),
            "environment {env:?} is deployed: a non-conformant id must still warn"
        );
    }
}

#[test]
#[serial(env)]
fn service_config_keys_default_empty_and_parse() {
    // No [keys] section -> empty identities (keyless node).
    let cfg = ServiceConfig::from_toml_str(SERVICE_TOML).unwrap();
    assert!(cfg.keys.identities.is_empty());

    // An explicit [keys].identities list parses into PathBufs in order.
    let with_keys = ServiceConfig::from_toml_str(
        r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"

[keys]
identities = ["keys/node.c4gh", "keys/node-prev.c4gh"]

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#,
    )
    .unwrap();
    assert_eq!(
        with_keys.keys.identities,
        vec![
            PathBuf::from("keys/node.c4gh"),
            PathBuf::from("keys/node-prev.c4gh"),
        ]
    );
    with_keys.preflight().unwrap();
}

#[test]
#[serial(env)]
fn override_dir_defaults_under_data_dir_and_parses() {
    // No override_dir: resolves to <data_dir>/overrides.
    let toml = r#"
[service]
data_dir = "/var/lib/gdi/datasets"
"#;
    let cfg = ServiceConfig::from_toml_str(toml).unwrap();
    assert_eq!(cfg.service.override_dir, None);
    assert_eq!(
        cfg.service.override_dir_resolved(),
        PathBuf::from("/var/lib/gdi/datasets/overrides")
    );

    // Explicit override_dir wins over the data_dir-derived default.
    let toml2 = r#"
[service]
data_dir = "/var/lib/gdi/datasets"
override_dir = "/etc/gdi/overrides"
"#;
    let cfg2 = ServiceConfig::from_toml_str(toml2).unwrap();
    assert_eq!(
        cfg2.service.override_dir_resolved(),
        PathBuf::from("/etc/gdi/overrides")
    );
}

#[test]
#[serial(env)]
fn relative_override_dir_is_rejected_at_preflight() {
    // A relative override_dir resolves against the process working directory, so the
    // operator CLI (run from a shell) and the node (working directory `/`) would read
    // different override stores — a recorded take-down the server never sees. `data_dir` is
    // already required absolute; the override root must be too. Without this check preflight
    // passes and the store silently fails open.
    let toml = r#"
[service]
base_url = "https://gdi.example.org"
data_dir = "/var/lib/gdi/datasets"
override_dir = "relative/overrides"

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#;
    let cfg = ServiceConfig::from_toml_str(toml).unwrap();
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(
        err.to_string().contains("override_dir"),
        "the rejection must name override_dir: {err}"
    );

    // The default (unset -> under the absolute data_dir) still preflights.
    let ok =
        ServiceConfig::from_toml_str(&toml.replace("override_dir = \"relative/overrides\"\n", ""))
            .unwrap();
    ok.preflight()
        .expect("default override_dir under an absolute data_dir is absolute");
}

#[test]
#[serial(env)]
fn require_override_store_defaults_off_and_parses() {
    // Default posture is off: a fresh node that has never recorded an override must start
    // with no store on disk.
    let toml = r#"
[service]
data_dir = "/var/lib/gdi/datasets"
"#;
    let cfg = ServiceConfig::from_toml_str(toml).unwrap();
    assert!(
        !cfg.service.require_override_store,
        "the presence assertion must be opt-in"
    );

    let toml2 = r#"
[service]
data_dir = "/var/lib/gdi/datasets"
require_override_store = true
"#;
    let cfg2 = ServiceConfig::from_toml_str(toml2).unwrap();
    assert!(cfg2.service.require_override_store);
}

#[test]
#[serial(env)]
fn otlp_headers_debug_redacts_values_but_keeps_names() {
    let cfg = ServiceConfig::from_toml_str(
        r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"
otlp_endpoint = "http://collector:4318"

[service.otlp_headers]
Authorization = "ApiKey SUPERSECRETVALUE"
"#,
    )
    .unwrap();

    // The value is preserved for the exporter to send...
    let headers = cfg.service.otlp_headers.as_ref().unwrap();
    assert_eq!(
        headers.0.get("Authorization").map(String::as_str),
        Some("ApiKey SUPERSECRETVALUE")
    );

    // ...but its `Debug` never renders the value (name shown, value redacted), so the
    // derived `Debug` on `ServiceSection` / a stray `debug!(?config)` cannot leak it.
    let dbg = format!("{:?}", cfg.service);
    assert!(dbg.contains("Authorization"), "header name is shown: {dbg}");
    assert!(
        !dbg.contains("SUPERSECRETVALUE"),
        "the header value must be redacted out of Debug: {dbg}"
    );
    assert!(
        dbg.contains("***"),
        "the redaction marker is present: {dbg}"
    );
}

#[test]
#[serial(env)]
fn otlp_headers_populate_from_env_overlay() {
    // The doc comment recommends the `GDI_NODE__SERVICE__OTLP_HEADERS__<NAME>` env overlay
    // as the preferred (secret-safe) way to set a header, so the transparent newtype
    // must still deserialize from figment's split env dict.
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "config.toml",
            r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"
otlp_endpoint = "http://collector:4318"
"#,
        )?;
        jail.set_env(
            "GDI_NODE__SERVICE__OTLP_HEADERS__AUTHORIZATION",
            "ApiKey env-secret",
        );
        let cfg = ServiceConfig::load(Some(Path::new("config.toml"))).unwrap();
        let headers = cfg.service.otlp_headers.as_ref().unwrap();
        assert_eq!(
            headers.0.get("authorization").map(String::as_str),
            Some("ApiKey env-secret"),
            "the env-overlay header must land in the newtype map"
        );
        Ok(())
    });
}

#[test]
#[serial(env)]
fn otlp_metrics_interval_populates_from_env_overlay() {
    // The metrics push is a deployment knob (a Secret-free one), so the env overlay
    // must reach it like every other `[service]` scalar.
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "config.toml",
            r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"
otlp_endpoint = "https://apm.example.org"
"#,
        )?;
        jail.set_env("GDI_NODE__SERVICE__OTLP_METRICS_INTERVAL_SECONDS", "30");
        let cfg = ServiceConfig::load(Some(Path::new("config.toml"))).unwrap();
        assert_eq!(cfg.service.otlp_metrics_interval_seconds, Some(30));
        Ok(())
    });
}

#[test]
fn preflight_pins_the_otlp_metrics_interval() {
    // Off by default; a positive interval with an endpoint is the working shape; zero
    // is a typo for "off" that would otherwise mean "export continuously". Set on the
    // parsed config rather than through `fairdp_toml`'s `extra`, which lands inside
    // `[fairdp]` — the same shape the plaintext-secret-header test uses.
    assert_eq!(
        ServiceConfig::default()
            .service
            .otlp_metrics_interval_seconds,
        None
    );
    let mut cfg = ServiceConfig::from_toml_str(&fairdp_toml("")).unwrap();
    cfg.service.otlp_endpoint = Some("https://apm.example.org".to_owned());

    cfg.service.otlp_metrics_interval_seconds = Some(60);
    cfg.preflight()
        .expect("a positive interval with an endpoint must preflight");

    cfg.service.otlp_metrics_interval_seconds = Some(0);
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(
        err.to_string().contains("otlp_metrics_interval_seconds"),
        "the error must name the field: {err}"
    );
}

#[test]
fn preflight_pins_the_otlp_trace_sample_ratio() {
    // Unset means every trace (the shape the node shipped with); any fraction of the unit
    // interval is accepted, including the two ends; outside it is a typo, not a policy.
    assert_eq!(
        ServiceConfig::default().service.otlp_trace_sample_ratio,
        None
    );
    let mut cfg = ServiceConfig::from_toml_str(&fairdp_toml("")).unwrap();
    cfg.service.otlp_endpoint = Some("https://apm.example.org".to_owned());
    for ok in [0.0, 0.25, 1.0] {
        cfg.service.otlp_trace_sample_ratio = Some(ok);
        cfg.preflight()
            .unwrap_or_else(|e| panic!("ratio {ok} must preflight: {e}"));
    }
    for bad in [-0.1, 1.5, f64::NAN] {
        cfg.service.otlp_trace_sample_ratio = Some(bad);
        let err = cfg.preflight().unwrap_err();
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
        assert!(
            err.to_string().contains("otlp_trace_sample_ratio"),
            "the error must name the field for {bad}: {err}"
        );
    }
}

#[test]
#[serial(env)]
fn service_config_parses_without_fairdp() {
    let cfg = ServiceConfig::from_toml_str(
        r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"

[catalogs]
synthetic-data = "Synthetic Data"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"
"#,
    )
    .unwrap();
    assert!(cfg.fairdp.is_none());
    cfg.preflight().unwrap();
}

/// Build a service config with a valid `[fairdp]` block, injecting `extra`
/// lines directly under the `[fairdp]` table header (so `[fairdp]`-level keys
/// such as `theme_taxonomy` land in the right table, not in a trailing nested
/// one). The base block is the preflight-passing minimum: title/issued/license
/// + complete publisher and HDAB contact points + a single in-scheme theme.
fn fairdp_toml(extra: &str) -> String {
    format!(
        r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"

[fairdp]
title = "GDI Estonia FAIR Data Point"
issued = "2026-01-01T00:00:00Z"
license = "https://creativecommons.org/licenses/by/4.0/"
theme = ["http://publications.europa.eu/resource/authority/data-theme/HEAL"]
applicable_legislation = ["http://data.europa.eu/eli/reg/2025/327/oj"]
{extra}

[fairdp.publisher]
name = "University of Tartu"
[fairdp.publisher.contact_point]
fn = "GDI Estonia"
has_email = "mailto:gdi@example.org"

[fairdp.hdab]
name = "Estonian HDAB"
[fairdp.hdab.contact_point]
fn = "Estonian HDAB"
has_email = "mailto:hdab@example.org"
"#
    )
}

#[test]
#[serial(env)]
fn fairdp_full_config_loads_and_preflights() {
    let cfg = ServiceConfig::from_toml_str(&fairdp_toml("")).unwrap();
    let fairdp = cfg.fairdp.as_ref().expect("[fairdp] present");
    assert_eq!(fairdp.title, "GDI Estonia FAIR Data Point");
    assert_eq!(fairdp.publisher.contact_point.fn_, "GDI Estonia");
    assert_eq!(
        fairdp.hdab.contact_point.has_email,
        "mailto:hdab@example.org"
    );
    cfg.preflight().unwrap();
}

/// `[fairdp].language` is optional with an English default, and any value that reaches the
/// emitter must be a real IRI.
///
/// It is emitted verbatim as `dct:language` on the FDP root, on every catalog and on
/// every dataset, so an empty or malformed value is a bad triple on every record the
/// harvester reads — which is why it is rejected at boot rather than at the first harvest.
/// The expected default is spelled out here rather than read from the constant: this test
/// exists to pin the value, and comparing the constant with itself would pin nothing.
#[test]
#[serial(env)]
fn fairdp_language_defaults_to_english_and_must_be_an_iri() {
    // Omitted entirely — `fairdp_toml("")` never mentions `language`.
    let cfg = ServiceConfig::from_toml_str(&fairdp_toml("")).unwrap();
    assert_eq!(
        cfg.fairdp.as_ref().unwrap().language,
        "http://publications.europa.eu/resource/authority/language/ENG",
        "an omitted [fairdp].language must default to the EU English authority IRI"
    );
    cfg.preflight().unwrap();

    // An explicit value is kept verbatim.
    let cfg = ServiceConfig::from_toml_str(&fairdp_toml(
        r#"language = "http://publications.europa.eu/resource/authority/language/EST""#,
    ))
    .unwrap();
    assert_eq!(
        cfg.fairdp.as_ref().unwrap().language,
        "http://publications.europa.eu/resource/authority/language/EST"
    );
    cfg.preflight().unwrap();

    // Empty and scheme-less values are refusals, not warnings.
    for bad in ["", "eng"] {
        let cfg = ServiceConfig::from_toml_str(&fairdp_toml(&format!("language = {bad:?}")))
            .unwrap_or_else(|e| panic!("language = {bad:?} must parse: {e}"));
        let err = cfg
            .preflight()
            .expect_err("a non-IRI [fairdp].language must fail preflight");
        assert!(
            err.to_string().contains("fairdp.language"),
            "the error must name the offending key; got: {err}"
        );
    }
}

/// `[fairdp].issued` is validated with a lenient RFC-3339 parser, which admits a space
/// separator and a lowercase `z` — forms outside the xsd:dateTime lexical space — yet is
/// emitted verbatim as `^^xsd:dateTime`. Load-time canonicalization normalizes any parseable
/// value so a strict SHACL harvester never silently drops the FDP-root/Catalog records over
/// an ill-typed literal.
#[test]
#[serial(env)]
fn fairdp_issued_is_canonicalized_to_xsd_datetime_at_load() {
    // A space separator (as pasted from a SQL/Postgres export) parses under RFC-3339
    // but is not canonical xsd:dateTime; it must be normalized to the `T`/`Z` form.
    let toml = fairdp_toml("").replace("2026-01-01T00:00:00Z", "2024-01-01 00:00:00Z");
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let issued = cfg.fairdp.as_ref().unwrap().issued.clone();
    assert!(
        issued.starts_with("2024-01-01T00:00:00") && issued.ends_with('Z') && !issued.contains(' '),
        "a space-separated issued must be canonicalized to xsd:dateTime form, got {issued:?}"
    );
    cfg.preflight().unwrap();

    // A lowercase zulu marker is likewise normalized to uppercase `Z`.
    let toml = fairdp_toml("").replace("2026-01-01T00:00:00Z", "2024-01-01T00:00:00z");
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let issued = cfg.fairdp.as_ref().unwrap().issued.clone();
    assert!(
        issued.ends_with('Z') && !issued.contains('z'),
        "a lowercase `z` must be canonicalized to uppercase `Z`, got {issued:?}"
    );

    // An already-canonical value is preserved byte-for-byte (idempotent).
    let cfg = ServiceConfig::from_toml_str(&fairdp_toml("")).unwrap();
    assert_eq!(cfg.fairdp.as_ref().unwrap().issued, "2026-01-01T00:00:00Z");
}

/// A `[catalogs]` entry whose title value is empty must be rejected at preflight: it would
/// otherwise serve a blank `dct:title`/`dct:description` on the Catalog record while
/// `/health` stays green.
#[test]
#[serial(env)]
fn empty_catalog_title_is_rejected() {
    let toml = fairdp_toml("") + "\n[catalogs]\ngdi-aggregated = \"\"\n";
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = cfg.preflight().unwrap_err();
    assert!(
        err.to_string().contains("[catalogs] title"),
        "expected an empty-catalog-title error, got: {err}"
    );

    // A non-empty title preflights cleanly.
    let toml = fairdp_toml("") + "\n[catalogs]\ngdi-aggregated = \"GoE aggregated\"\n";
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
}

/// `FairdpConfig::theme_taxonomy_iri` derives the Catalog `dcat:themeTaxonomy` from the
/// first `theme`'s parent path when `theme_taxonomy` is unset, returns `None` when there is
/// nothing to derive from (no themes, or a theme with no derivable parent path), strips a
/// trailing slash before taking the parent — without which the derived scheme is the concept
/// itself, one level too deep — and lets an explicit `theme_taxonomy` override win.
#[test]
fn fairdp_config_theme_taxonomy_iri_derives_or_overrides() {
    let mut fairdp = FairdpConfig::default();
    assert_eq!(fairdp.theme_taxonomy_iri(), None, "no themes, no override");

    fairdp.theme =
        vec!["http://publications.europa.eu/resource/authority/data-theme/HEAL".to_owned()];
    assert_eq!(
        fairdp.theme_taxonomy_iri().as_deref(),
        Some("http://publications.europa.eu/resource/authority/data-theme"),
        "derives the taxonomy from the first theme's parent path"
    );

    // A trailing slash is a normal way to write an IRI, and without stripping it first
    // the "parent path" comes out as the concept itself — one level too deep, silently:
    // the published `dcat:themeTaxonomy` is well-formed and resolvable but names the
    // wrong resource, so a harvester reads a concept where a ConceptScheme belongs.
    fairdp.theme =
        vec!["http://publications.europa.eu/resource/authority/data-theme/HEAL/".to_owned()];
    assert_eq!(
        fairdp.theme_taxonomy_iri().as_deref(),
        Some("http://publications.europa.eu/resource/authority/data-theme"),
        "a trailing slash must not shift the derived scheme down a level"
    );

    fairdp.theme = vec!["no-slash-here".to_owned()];
    assert_eq!(
        fairdp.theme_taxonomy_iri(),
        None,
        "a theme with no parent path has nothing to derive"
    );

    fairdp.theme_taxonomy = Some("http://example.org/custom-scheme".to_owned());
    assert_eq!(
        fairdp.theme_taxonomy_iri().as_deref(),
        Some("http://example.org/custom-scheme"),
        "an explicit override wins over derivation"
    );
}

/// `[fairdp]` structural validation: an empty `theme`, a missing publisher/HDAB
/// contact point, or a non-`mailto:` contact email would each serve
/// SHACL-non-conformant RDF, so preflight must reject all four.
///
/// Each row is the valid `fairdp_toml("")` fixture with exactly one field broken, so the
/// case states its defect instead of restating a whole config around it. (A perturbation
/// that failed to apply cannot weaken a row: the untouched fixture preflights cleanly,
/// so the row's expected failure would not materialize.)
#[test]
#[serial(env)]
fn preflight_validates_fairdp_contact_points_and_theme() {
    // The two contact-point sub-tables, verbatim from `fairdp_toml`, so a case can drop one.
    const PUBLISHER_CONTACT: &str = r#"[fairdp.publisher.contact_point]
fn = "GDI Estonia"
has_email = "mailto:gdi@example.org"
"#;
    const HDAB_CONTACT: &str = r#"[fairdp.hdab.contact_point]
fn = "Estonian HDAB"
has_email = "mailto:hdab@example.org"
"#;
    // The publisher contact point's email (the one `mailto:gdi@example.org` in the fixture).
    const PUBLISHER_EMAIL: &str = r#"has_email = "mailto:gdi@example.org""#;
    let cases = [
        (
            "empty_theme",
            fairdp_toml("").replace(
                r#"theme = ["http://publications.europa.eu/resource/authority/data-theme/HEAL"]"#,
                "theme = []",
            ),
            Expect::Fail("fairdp.theme"),
        ),
        (
            // A publisher with no [contact_point] sub-table -> empty fn/has_email.
            "missing_publisher_contact_point",
            fairdp_toml("").replace(PUBLISHER_CONTACT, ""),
            Expect::Fail("fairdp.publisher.contact_point"),
        ),
        (
            "missing_hdab_contact_point",
            fairdp_toml("").replace(HDAB_CONTACT, ""),
            Expect::Fail("fairdp.hdab.contact_point"),
        ),
        (
            // Override the publisher contact point's email with a non-mailto value.
            "bad_contact_email",
            fairdp_toml("").replace(PUBLISHER_EMAIL, r#"has_email = "gdi@example.org""#),
            Expect::Fail("has_email"),
        ),
        (
            // A contact point with a non-empty `fn` but no `has_email` at all (rather
            // than a malformed one) must hit the dedicated empty-field check, not the
            // mailto-pattern check.
            "publisher_contact_empty_has_email",
            fairdp_toml("").replace(PUBLISHER_EMAIL, r#"has_email = """#),
            Expect::Fail("has_email"),
        ),
        (
            // `has_email` matching the loose `.+@.+\..+` mailto pattern but carrying an
            // IRIREF-forbidden character (here, an embedded space) must still be rejected:
            // the pattern check alone is not enough.
            "publisher_contact_has_email_iri_unsafe_char",
            fairdp_toml("").replace(PUBLISHER_EMAIL, r#"has_email = "mailto:a b@example.org""#),
            Expect::Fail("not allowed in an IRI"),
        ),
    ];
    for (label, toml, expect) in cases {
        assert_preflight_case(label, &toml, &expect);
    }
}

/// `[beacon]` scalar-field validation: `environment` is the GA4GH `beaconInfoResults`
/// required closed enum; the mount base paths must be canonical (router mounts at
/// their normalized form); `api_version` is pinned to the vendored framework version.
/// Each field is injected (one at a time) at the same anchor point in the
/// representative fairdp config.
#[test]
#[serial(env)]
fn preflight_validates_beacon_scalar_fields() {
    // Inject a line into the otherwise-valid `[beacon]` block.
    let with_line = |line: &str| {
        fairdp_toml("").replace(
            "name = \"GDI Estonia Beacon\"",
            &format!("name = \"GDI Estonia Beacon\"\n{line}"),
        )
    };
    let cases = [
        // environment: a mistyped or empty value is rejected, naming the field.
        (
            "environment=production (mistyped)",
            r#"environment = "production""#,
            Expect::Fail("beacon.environment"),
        ),
        (
            "environment=PROD (wrong case)",
            r#"environment = "PROD""#,
            Expect::Fail("beacon.environment"),
        ),
        (
            "environment=Test (wrong case)",
            r#"environment = "Test""#,
            Expect::Fail("beacon.environment"),
        ),
        (
            "environment empty",
            r#"environment = """#,
            Expect::Fail("beacon.environment"),
        ),
        // environment: each valid enum value preflights cleanly.
        ("environment=prod", r#"environment = "prod""#, Expect::Pass),
        ("environment=test", r#"environment = "test""#, Expect::Pass),
        ("environment=dev", r#"environment = "dev""#, Expect::Pass),
        (
            "environment=staging",
            r#"environment = "staging""#,
            Expect::Pass,
        ),
        // aggregated_base_path: non-canonical forms are each rejected, naming the field.
        (
            "base_path missing leading slash",
            r#"aggregated_base_path = "beacon/v2""#,
            Expect::Fail("aggregated_base_path"),
        ),
        (
            "base_path trailing slash",
            r#"aggregated_base_path = "/beacon/v2/""#,
            Expect::Fail("aggregated_base_path"),
        ),
        (
            "base_path empty",
            r#"aggregated_base_path = """#,
            Expect::Fail("aggregated_base_path"),
        ),
        (
            "base_path root only",
            r#"aggregated_base_path = "/""#,
            Expect::Fail("aggregated_base_path"),
        ),
        (
            "base_path empty segment",
            r#"aggregated_base_path = "/beacon//v2""#,
            Expect::Fail("aggregated_base_path"),
        ),
        (
            "base_path contains space",
            r#"aggregated_base_path = "/beacon v2""#,
            Expect::Fail("aggregated_base_path"),
        ),
        // An IRIREF-forbidden delimiter must be rejected: the base path is emitted verbatim
        // into served DCAT/Turtle, so `>` would break out of the IRI and inject triples.
        // Whitespace is caught above; this covers the graph-breakout delimiters.
        (
            "base_path contains IRI breakout >",
            r#"aggregated_base_path = "/beacon/v2>injected""#,
            Expect::Fail("aggregated_base_path"),
        ),
        (
            "base_path contains IRI breakout <",
            r#"aggregated_base_path = "/beacon/<v2""#,
            Expect::Fail("aggregated_base_path"),
        ),
        // aggregated_base_path: canonical forms preflight cleanly.
        (
            "base_path canonical /beacon/v2",
            r#"aggregated_base_path = "/beacon/v2""#,
            Expect::Pass,
        ),
        (
            "base_path canonical /beacon",
            r#"aggregated_base_path = "/beacon""#,
            Expect::Pass,
        ),
        (
            "base_path canonical /b/v2",
            r#"aggregated_base_path = "/b/v2""#,
            Expect::Pass,
        ),
        // api_version: pinned to the vendored framework version.
        (
            "api_version stale",
            r#"api_version = "v2.1.0""#,
            Expect::Fail("api_version"),
        ),
        (
            "api_version future",
            r#"api_version = "v3.0.0""#,
            Expect::Fail("api_version"),
        ),
        (
            "api_version missing v prefix",
            r#"api_version = "2.2.0""#,
            Expect::Fail("api_version"),
        ),
        (
            "api_version empty",
            r#"api_version = """#,
            Expect::Fail("api_version"),
        ),
        (
            "api_version pinned value",
            r#"api_version = "v2.2.0""#,
            Expect::Pass,
        ),
        // sensitive_base_path is validated by the same canonical-mount-form rule as
        // aggregated_base_path, but through a separate call site — cover it directly
        // rather than relying on aggregated_base_path's coverage to imply it.
        (
            "sensitive_base_path missing leading slash",
            r#"sensitive_base_path = "sensitive/v2""#,
            Expect::Fail("sensitive_base_path"),
        ),
        (
            "sensitive_base_path canonical override accepted",
            r#"sensitive_base_path = "/sensitive/v2""#,
            Expect::Pass,
        ),
    ];
    for (label, line, expect) in cases {
        let toml = with_line(line);
        assert_preflight_case(label, &toml, &expect);
    }
    // The representative defaults (no explicit override of any of the three fields)
    // still preflight, and the default `environment` is `prod` — a node booted
    // without these fields serves a conformant `/info`.
    let cfg = ServiceConfig::from_toml_str(&fairdp_toml("")).unwrap();
    assert_eq!(cfg.beacon.environment, "prod");
    cfg.preflight()
        .expect("default beacon scalar fields must preflight");
}

/// A config still carrying a `<SET ME …>` quickstart placeholder is unfinished:
/// preflight must reject it fast and name the field, so an operator who copied
/// `node.quickstart.toml` and missed a value fails the `check-config` gate
/// instead of booting a node with a placeholder identity.
#[test]
#[serial(env)]
fn preflight_rejects_unreplaced_placeholder() {
    let toml = fairdp_toml("").replace(
        "name = \"GDI Estonia Beacon\"",
        "name = \"<SET ME: your beacon name>\"",
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(
        err.to_string().contains("beacon.name"),
        "placeholder error must name the field: {err}"
    );
    assert!(
        err.to_string().contains("placeholder"),
        "placeholder error must identify it as a placeholder: {err}"
    );
}

/// `[service].cors_allowed_origins` validation: empty is the wildcard default; a
/// non-empty list must be `["*"]` alone or exact canonical HTTP(S) origins. A
/// non-canonical origin (trailing slash, path, explicit default port, uppercase
/// scheme) is rejected at boot because it would silently never match the browser
/// `Origin` header the CORS layer compares it against.
#[test]
#[serial(env)]
fn preflight_validates_cors_allowed_origins() {
    // Inject a `cors_allowed_origins` line into the otherwise-valid `[service]` block.
    let with_line = |line: &str| {
        fairdp_toml("").replace(
            "data_dir = \"/data\"",
            &format!("data_dir = \"/data\"\n{line}"),
        )
    };
    let cases = [
        // Accepted forms.
        (
            "empty (default wildcard)",
            "cors_allowed_origins = []",
            Expect::Pass,
        ),
        (
            "explicit wildcard alone",
            r#"cors_allowed_origins = ["*"]"#,
            Expect::Pass,
        ),
        (
            "single https origin",
            r#"cors_allowed_origins = ["https://portal.example.org"]"#,
            Expect::Pass,
        ),
        (
            "origin with explicit non-default port",
            r#"cors_allowed_origins = ["https://portal.example.org:8443"]"#,
            Expect::Pass,
        ),
        (
            "http localhost dev origin with port",
            r#"cors_allowed_origins = ["http://localhost:5173"]"#,
            Expect::Pass,
        ),
        (
            "two distinct origins",
            r#"cors_allowed_origins = ["https://a.example.org", "https://b.example.org"]"#,
            Expect::Pass,
        ),
        // Rejected forms — each names the field.
        (
            "wildcard mixed with a specific origin",
            r#"cors_allowed_origins = ["*", "https://a.example.org"]"#,
            Expect::Fail("cors_allowed_origins"),
        ),
        (
            "empty entry",
            r#"cors_allowed_origins = ["https://a.example.org", ""]"#,
            Expect::Fail("cors_allowed_origins"),
        ),
        (
            "trailing slash",
            r#"cors_allowed_origins = ["https://portal.example.org/"]"#,
            Expect::Fail("cors_allowed_origins"),
        ),
        (
            "carries a path",
            r#"cors_allowed_origins = ["https://portal.example.org/beacon"]"#,
            Expect::Fail("cors_allowed_origins"),
        ),
        (
            "non-http(s) scheme",
            r#"cors_allowed_origins = ["ftp://portal.example.org"]"#,
            Expect::Fail("cors_allowed_origins"),
        ),
        (
            "bare host, not a url",
            r#"cors_allowed_origins = ["portal.example.org"]"#,
            Expect::Fail("cors_allowed_origins"),
        ),
        (
            "uppercase scheme (non-canonical)",
            r#"cors_allowed_origins = ["HTTPS://portal.example.org"]"#,
            Expect::Fail("cors_allowed_origins"),
        ),
        (
            "explicit default port (non-canonical)",
            r#"cors_allowed_origins = ["https://portal.example.org:443"]"#,
            Expect::Fail("cors_allowed_origins"),
        ),
    ];
    for (label, line, expect) in cases {
        assert_preflight_case(label, &with_line(line), &expect);
    }
}

/// The placeholder scan reports every unreplaced field at once, so `check-config`
/// hands the operator the whole checklist rather than one field per re-run.
#[test]
#[serial(env)]
fn preflight_placeholder_scan_reports_all_fields() {
    let toml = fairdp_toml("")
        .replace(
            "id = \"ee.ut.af-beacon.production\"",
            "id = \"<SET ME: org.example.beacon>\"",
        )
        .replace(
            "name = \"GDI Estonia Beacon\"",
            "name = \"<SET ME: your beacon name>\"",
        );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let msg = cfg.preflight().unwrap_err().to_string();
    assert!(msg.contains("beacon.id"), "must list beacon.id: {msg}");
    assert!(msg.contains("beacon.name"), "must list beacon.name: {msg}");
}

/// A fully-filled config (no sentinel) is not falsely flagged.
#[test]
#[serial(env)]
fn preflight_accepts_config_without_placeholders() {
    let cfg = ServiceConfig::from_toml_str(&fairdp_toml("")).unwrap();
    cfg.preflight()
        .expect("placeholder-free config must preflight");
}

/// A `<SET ME …>` placeholder nested inside an array field (here `fairdp.theme`) must be
/// reported by the placeholder scan: the walk has to recurse into
/// `serde_json::Value::Array`, not just objects and string leaves. Without the array arm the
/// sentinel is invisible and preflight's placeholder gate lets it through.
#[test]
#[serial(env)]
fn preflight_rejects_placeholder_inside_array_field() {
    let toml = fairdp_toml("").replace(
        "theme = [\"http://publications.europa.eu/resource/authority/data-theme/HEAL\"]",
        "theme = [\"<SET ME: theme concept IRI>\"]",
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    let msg = err.to_string();
    assert!(
        msg.contains("placeholder"),
        "an array-nested sentinel must be reported as a placeholder, got: {msg}"
    );
    assert!(
        msg.contains("fairdp.theme[0]"),
        "the placeholder report must name the array element path, got: {msg}"
    );
}

/// A `[fairdp].issued` that is not a well-formed `xsd:dateTime` (RFC-3339
/// instant) must be rejected — it is emitted verbatim as `"…"^^xsd:dateTime`
/// and an operator typo would fail the FDP/gdi-metadata SHACL while the node
/// served 200s.
#[test]
#[serial(env)]
fn preflight_rejects_malformed_fairdp_issued() {
    for bad in ["2026-01-01", "Jan 2026", "not-a-date"] {
        let toml = fairdp_toml("").replace(
            r#"issued = "2026-01-01T00:00:00Z""#,
            &format!("issued = {bad:?}"),
        );
        let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
        let err = cfg.preflight().unwrap_err();
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
        assert!(
            err.to_string().contains("fairdp.issued"),
            "error should name fairdp.issued for {bad:?}: {err}"
        );
    }
    // A well-formed RFC-3339 instant still passes.
    let cfg = ServiceConfig::from_toml_str(&fairdp_toml("")).unwrap();
    cfg.preflight().unwrap();
}

#[test]
#[serial(env)]
fn preflight_rejects_a_non_http_base_url() {
    // `base_url` is the subject IRI of every published FDP record, so it is handed to
    // whatever renders those records as a link, and it passes the same scheme allow-list its
    // neighbours do rather than only "parses as a URL".
    for bad in [
        "javascript:alert(1)",
        "data:text/plain,x",
        "file:///etc/passwd",
    ] {
        let toml = format!(
            r#"
[service]
base_url = "{bad}"
data_dir = "/data"

[beacon]
id = "org.test.beacon"
name = "Test"
"#
        );
        let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
        let err = cfg
            .preflight()
            .expect_err("a non-http base_url must be rejected");
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    }
    // http/https still pass.
    for good in ["https://n.example.org", "http://localhost:8080"] {
        let toml = format!(
            r#"
[service]
base_url = "{good}"
data_dir = "/data"

[beacon]
id = "org.test.beacon"
name = "Test"
"#
        );
        ServiceConfig::from_toml_str(&toml)
            .unwrap()
            .preflight()
            .unwrap_or_else(|e| panic!("{good} must stay legal: {e}"));
    }
}

/// The five optional Beacon `/info` links pass the same scheme test `base_url` does — all
/// five together, or none: validating two would teach a reader the other three are checked
/// too. Each case below places the bad value inside the one occurrence of the table it
/// belongs to (TOML forbids re-opening a table with a second `[header]`), rather than
/// appending a duplicate `[beacon]`/`[beacon.organization]` header after a fully-written one.
#[test]
#[serial(env)]
fn preflight_rejects_a_non_http_info_url_on_every_optional_link() {
    let cases: [(&str, &str); 5] = [
        ("beacon.documentation_url", "documentation_url"),
        ("beacon.alternative_url", "alternative_url"),
        ("beacon.organization.welcome_url", "welcome_url"),
        ("beacon.organization.contact_url", "contact_url"),
        ("beacon.organization.logo_url", "logo_url"),
    ];
    for (field, key) in cases {
        for bad in [
            "javascript:alert(1)",
            "data:text/plain,x",
            "file:///etc/passwd",
            "not a url",
        ] {
            let toml = if field.starts_with("beacon.organization.") {
                format!(
                    r#"
[service]
base_url = "https://node.example.org"
data_dir = "/data"

[beacon]
id = "org.test.beacon"
name = "Test"

[beacon.organization]
id = "org.test"
name = "Test Org"
{key} = "{bad}"
"#
                )
            } else {
                format!(
                    r#"
[service]
base_url = "https://node.example.org"
data_dir = "/data"

[beacon]
id = "org.test.beacon"
name = "Test"
{key} = "{bad}"

[beacon.organization]
id = "org.test"
name = "Test Org"
"#
                )
            };
            let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
            let err = cfg
                .preflight()
                .expect_err(&format!("{field} = {bad:?} must be rejected"));
            assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
            assert!(
                err.to_string().contains(field),
                "the error names {field}: {err}"
            );
        }
    }
}

/// `http`/`https` still pass on all five links, and `contact_url` additionally accepts a
/// well-formed `mailto:` address — but a `mailto:` is a contact, not a web link, so the
/// other four must keep rejecting it. The scheme is matched case-insensitively (RFC 3986
/// §3.1), so `MAILTO:`/`Mailto:` behave identically to `mailto:` on every field.
#[test]
#[serial(env)]
fn preflight_accepts_http_info_urls_and_a_mailto_contact_url() {
    let toml = r#"
[service]
base_url = "https://node.example.org"
data_dir = "/data"

[beacon]
id = "org.test.beacon"
name = "Test"
documentation_url = "https://docs.example.org"
alternative_url = "http://alt.example.org/beacon"

[beacon.organization]
id = "org.test"
name = "Test Org"
welcome_url = "https://example.org"
contact_url = "mailto:gdi@example.org"
logo_url = "https://example.org/logo.png"
"#;
    ServiceConfig::from_toml_str(toml)
        .unwrap()
        .preflight()
        .unwrap();
    // An uppercase scheme on contact_url is accepted just like the lowercase one.
    let upper_contact = toml.replace(
        r#"contact_url = "mailto:gdi@example.org""#,
        r#"contact_url = "MAILTO:gdi@example.org""#,
    );
    ServiceConfig::from_toml_str(&upper_contact)
        .unwrap()
        .preflight()
        .unwrap();
    // A mailto: is a contact, not a logo/doc/welcome link.
    let toml = toml.replace(
        r#"logo_url = "https://example.org/logo.png""#,
        r#"logo_url = "mailto:x@example.org""#,
    );
    let err = ServiceConfig::from_toml_str(&toml)
        .unwrap()
        .preflight()
        .expect_err("mailto logo rejected");
    assert!(
        err.to_string().contains("beacon.organization.logo_url"),
        "{err}"
    );
    // An uppercase scheme on a non-contact field is rejected too, naming only http/https —
    // it must not claim mailto is allowed there.
    let upper_logo = toml.replace(
        r#"logo_url = "mailto:x@example.org""#,
        r#"logo_url = "MAILTO:x@example.org""#,
    );
    let err = ServiceConfig::from_toml_str(&upper_logo)
        .unwrap()
        .preflight()
        .expect_err("uppercase mailto logo rejected");
    let msg = err.to_string();
    assert!(msg.contains("expected http or https"), "{msg}");
    assert!(!msg.contains("or mailto"), "{msg}");
    // A malformed mailto contact is rejected too.
    let toml = toml.replace(
        r#"contact_url = "mailto:gdi@example.org""#,
        r#"contact_url = "mailto:not-an-address""#,
    );
    let err = ServiceConfig::from_toml_str(&toml)
        .unwrap()
        .preflight()
        .expect_err("bad mailto rejected");
    assert!(
        err.to_string().contains("beacon.organization.contact_url"),
        "{err}"
    );
    // Case-insensitivity applies to a malformed mailto contact too.
    let toml = toml.replace(
        r#"contact_url = "mailto:not-an-address""#,
        r#"contact_url = "Mailto:not-an-address""#,
    );
    let err = ServiceConfig::from_toml_str(&toml)
        .unwrap()
        .preflight()
        .expect_err("bad uppercase-scheme mailto rejected");
    assert!(err.to_string().contains("well-formed mailto"), "{err}");
}

/// The smallest config that preflights: the required `[service]` fields plus the two
/// GA4GH-required `[beacon]` identity strings, with `service_extra` lines spliced into
/// the `[service]` block. The narrow-scope preflight cases below each perturb one knob on
/// top of it — via `service_extra`, or by appending (which lands in `[beacon]`, or opens a
/// new table of its own).
fn minimal_toml(service_extra: &str) -> String {
    format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "/data"
{service_extra}

[beacon]
id = "org.test.beacon"
name = "Test"
"#
    )
}

#[test]
#[serial(env)]
fn preflight_rejects_an_entirely_unbounded_quarantine() {
    // `rejected_retention_hours` and `rejected_max_count` each document 0 as "unbounded"
    // and cite the other as the bound that still applies — a rationale that holds for
    // either alone and collapses when both are 0, leaving the quarantine directory to grow
    // by a full rejected package per bad drop, forever, on the served-data volume. Neither
    // field can notice on its own, so the pair is checked together.
    let toml = minimal_toml("rejected_retention_hours = 0\nrejected_max_count = 0");
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(
        err.to_string().contains("rejected_retention_hours")
            && err.to_string().contains("rejected_max_count"),
        "the error must name both halves of the pair: {err}"
    );

    // Either one alone still means "unbounded on this axis, bounded on the other".
    for line in ["rejected_retention_hours = 0", "rejected_max_count = 0"] {
        ServiceConfig::from_toml_str(&minimal_toml(line))
            .unwrap()
            .preflight()
            .unwrap_or_else(|e| panic!("{line} alone must stay legal: {e}"));
    }
}

/// `max_visibility_staleness_seconds` must exceed the cadence at which the clock it bounds
/// advances (`full_poll_interval + marker_poll_interval`, per bucket): at or below it the
/// channel reads stale for most of every cycle and every dataset it owns drops out of the
/// public plane as empty 200s. The floor the predicate enforces is `> cadence`, and the
/// message must name that floor exactly, or it states one rule and applies another.
#[test]
#[serial(env)]
fn preflight_relates_visibility_staleness_to_the_poll_cadence() {
    // full 300 + marker 30 = cadence 330.
    let with_staleness = |staleness: u64| {
        minimal_toml(&format!("max_visibility_staleness_seconds = {staleness}"))
            + r#"
[[s3.buckets]]
name = "primary"
endpoint = "https://s3.example.org"
bucket = "gdi-datasets"
full_poll_interval = 300
marker_poll_interval = 30
"#
    };
    for (label, staleness, expect) in [
        ("the default, far above the cadence", 86_400, Expect::Pass),
        ("one above the cadence is the floor", 331, Expect::Pass),
        ("zero disables the bound", 0, Expect::Pass),
        (
            "equal to the cadence",
            330,
            Expect::Fail("at or below the poll cadence"),
        ),
        (
            "below the cadence",
            60,
            Expect::Fail("at or below the poll cadence"),
        ),
        // The message states the floor the predicate applies, not a vaguer one.
        (
            "the message names the exact floor",
            330,
            Expect::Fail("Raise it above 330"),
        ),
    ] {
        assert_preflight_case(label, &with_staleness(staleness), &expect);
    }
}

/// `query_concurrency` decouples the Beacon scan fan-out from `ingest_concurrency`, and
/// defaults to following it so an existing config keeps its behaviour.
///
/// Without the decoupling, tuning ingest throughput also widens public query concurrency —
/// the axis that multiplies query memory.
#[test]
#[serial(env)]
fn query_concurrency_defaults_to_ingest_concurrency_and_can_decouple() {
    // Absent: follows ingest_concurrency, whatever that is.
    let cfg = ServiceConfig::from_toml_str(&minimal_toml("ingest_concurrency = 7")).unwrap();
    assert_eq!(cfg.service.query_concurrency, None, "absent by default");
    assert_eq!(
        cfg.service.query_concurrency(),
        7,
        "an unset query_concurrency must follow ingest_concurrency exactly"
    );

    // Set: decoupled, and ingest is unaffected.
    let cfg = ServiceConfig::from_toml_str(&minimal_toml(
        "ingest_concurrency = 7\nquery_concurrency = 2",
    ))
    .unwrap();
    assert_eq!(cfg.service.query_concurrency(), 2);
    assert_eq!(
        cfg.service.ingest_concurrency, 7,
        "setting the query cap must not move the ingest cap"
    );

    // 0 would admit no scans at all: rejected at boot, not at the first query.
    let err = ServiceConfig::from_toml_str(&minimal_toml("query_concurrency = 0"))
        .unwrap()
        .preflight()
        .unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(
        err.to_string().contains("query_concurrency"),
        "the error must name the field: {err}"
    );
}

/// The process-wide scan-row budget must be at least as large as the per-request one.
/// A smaller global budget could never admit a request that used its full per-request
/// allowance, so the node would shed queries it advertises as servable — a config that
/// boots green and then 503s under load.
#[test]
#[serial(env)]
fn preflight_rejects_total_query_budget_below_per_request() {
    let toml = minimal_toml("max_query_bytes = 2048\nmax_total_query_bytes = 1024");
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(
        err.to_string().contains("max_total_query_bytes")
            && err.to_string().contains("max_query_bytes"),
        "the error must name both halves of the relation: {err}"
    );

    // Equal is legal: a single request may consume the entire process budget.
    ServiceConfig::from_toml_str(&minimal_toml(
        "max_query_bytes = 2048\nmax_total_query_bytes = 2048",
    ))
    .unwrap()
    .preflight()
    .expect("total == per-request must stay legal");
}

#[test]
#[serial(env)]
fn preflight_rejects_zero_request_bounds() {
    // 0 silently turns the node into a shed-everything / timeout-everything service (the
    // request bounds), or rejects every package permanently (the package caps); the other
    // duration knobs are floored to >= 1, so these must be too.
    //
    // The parquet caps and the request-body cap are the same footgun: a 0 body cap
    // 413s every POST beacon query, and a 0 parquet cap rejects every non-empty data
    // file (strict `>` at `validate_parquet.rs`) — the node boots green and passes
    // `check-config`, yet serves zero variant data. Guard them the same way.
    for key in [
        "request_timeout_seconds",
        "max_concurrent_requests",
        "max_query_bytes",
        "max_query_rows",
        "max_package_bytes",
        "max_package_members",
        "max_request_body_bytes",
        "max_parquet_file_bytes",
        "max_parquet_decompressed_bytes",
        "max_parquet_row_group_bytes",
    ] {
        let toml = minimal_toml(&format!("{key} = 0"));
        let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
        let err = cfg.preflight().unwrap_err();
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
        assert!(
            err.to_string().contains(key),
            "error should name {key}: {err}"
        );
    }
}

/// The beacon pagination knobs are a silent serve-nothing footgun. `max_page_limit = 0`
/// clamps every `g_variants`/`datasets` page to 0 records (the `Some(0)` "unbounded"
/// sentinel also resolves to `max_page_limit`), and `default_page_limit = 0` does the same
/// for the common no-limit query, while `check-config` and `/health` stay green. A
/// `default_page_limit` above `max_page_limit` is also incoherent, since the default is
/// silently clamped down. Reject all three at preflight.
#[test]
#[serial(env)]
fn preflight_rejects_incoherent_beacon_page_limits() {
    // Appending to the fixture lands inside its trailing `[beacon]` table.
    let base = minimal_toml("");
    // A zero on either knob is rejected, naming the offending field.
    for (field, block) in [
        ("beacon.max_page_limit", "max_page_limit = 0"),
        ("beacon.default_page_limit", "default_page_limit = 0"),
    ] {
        let cfg = ServiceConfig::from_toml_str(&format!("{base}{block}\n")).unwrap();
        let err = cfg.preflight().unwrap_err();
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
        assert!(
            err.to_string().contains(field),
            "error should name {field}: {err}"
        );
    }

    // default above max is incoherent and rejected.
    let cfg = ServiceConfig::from_toml_str(&format!(
        "{base}max_page_limit = 10\ndefault_page_limit = 50\n"
    ))
    .unwrap();
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(
        err.to_string().contains("default_page_limit"),
        "error should name default_page_limit: {err}"
    );

    // The representative defaults (10 / 1000) preflight cleanly.
    ServiceConfig::from_toml_str(&base)
        .unwrap()
        .preflight()
        .unwrap();
}

#[test]
#[serial(env)]
fn preflight_rejects_unsafe_catalog_map_key() {
    // A `[catalogs]` map key becomes a public `/fairdp` root IRI via
    // `NamedNode::new_unchecked`, so an unsafe key must fail boot rather than emit
    // SHACL-non-conformant RDF while `/health` stays green.
    let base = minimal_toml("");
    // The real-world catalog-name shapes preflight cleanly.
    let good = format!(
        "{base}\n[catalogs]\n\"gdi-aggregated\" = \"GoE Aggregated\"\n\"cat.v2\" = \"Catalog v2\"\n"
    );
    ServiceConfig::from_toml_str(&good)
        .unwrap()
        .preflight()
        .unwrap();

    // Each unsafe key (space / traversal / leading dot / separator) is rejected,
    // naming the offending `[catalogs]` key.
    for bad in ["bad key", "../escape", ".hidden", "a/b"] {
        let toml = format!("{base}\n[catalogs]\n{bad:?} = \"x\"\n");
        let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
        let err = cfg.preflight().unwrap_err();
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
        assert!(
            err.to_string().contains("[catalogs]"),
            "error should name [catalogs] for {bad:?}: {err}"
        );
    }
}

#[test]
#[serial(env)]
fn preflight_rejects_half_s3_credentials() {
    // access_key_id without secret_access_key (or vice versa) must fail fast,
    // not produce an opaque auth error at first poll.
    let toml = minimal_toml("")
        + r#"
[[s3.buckets]]
name = "primary"
endpoint = "https://s3.example.org"
bucket = "gdi-datasets"
access_key_id = "AKIAEXAMPLE"
"#;
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    let msg = err.to_string();
    assert!(
        msg.contains("primary") && msg.contains("credential"),
        "error should name the bucket + the credential pairing: {err}"
    );
}

/// A `prefix` that `object_store::path::Path` would rewrite must be rejected at boot.
///
/// Every rejected spelling here normalizes to a different keyspace than the one written:
/// a leading `/`, `//` and `.`/`..` segments are collapsed, and the characters AWS/GCS
/// advise against are percent-encoded (`a#b` ⇒ `a%23b`). The node would then monitor a
/// prefix the bucket policy does not grant and no other writer addresses — presenting as
/// an empty listing on a channel whose config looks right, which is why it fails at boot
/// rather than at first poll. The accepted spellings are the ones that round-trip intact,
/// including the documented `gdi-node-storage/`.
#[test]
#[serial(env)]
fn preflight_validates_the_s3_bucket_prefix() {
    let with_prefix = |prefix: &str| {
        let toml = minimal_toml("")
            + &format!(
                r#"
[[s3.buckets]]
name = "primary"
endpoint = "https://s3.example.org"
bucket = "gdi-datasets"
prefix = "{prefix}"
"#
            );
        ServiceConfig::from_toml_str(&toml).unwrap().preflight()
    };

    for accepted in [
        "",
        "gdi-node-storage/",
        "gdi-node-storage",
        "a/b/c",
        "node_1.test-2/",
    ] {
        assert!(
            with_prefix(accepted).is_ok(),
            "prefix {accepted:?} round-trips unchanged and must be accepted"
        );
    }

    for (rejected, why) in [
        ("/gdi-node-storage/", "start with '/'"),
        ("a//b", "empty segment"),
        // A trailing run of slashes is the same silent renormalization as `a//` in the
        // middle: `Path::from` drops empty segments, so this reaches the wire as `a/` while
        // the operator, and any bucket policy granting `a//*`, say otherwise. One optional
        // trailing slash is still fine, asserted in the accepted list above.
        ("a//", "empty segment"),
        ("gdi-node-storage///", "empty segment"),
        ("a/../b", "'.' and '..'"),
        ("..", "'.' and '..'"),
        ("a#b/", "'#'"),
        ("a b/", "' '"),
    ] {
        let Err(err) = with_prefix(rejected) else {
            panic!("prefix {rejected:?} normalizes to a different keyspace and must be rejected")
        };
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
        let msg = err.to_string();
        assert!(
            msg.contains("primary") && msg.contains(why),
            "the error for {rejected:?} should name the bucket and {why}: {err}"
        );
    }
}

/// An `[[s3.buckets]]` entry with an empty `name` must fail preflight fast: `name` keys
/// Vault-backed credentials, channel ownership and the `gdi_s3_*{channel}` metric label, so
/// an empty value would collide with any other empty-named entry, or produce an unlabelled
/// metric series.
#[test]
#[serial(env)]
fn preflight_rejects_empty_s3_bucket_name() {
    let toml = minimal_toml("")
        + r#"
[[s3.buckets]]
name = ""
"#;
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(
        err.to_string().contains("empty name"),
        "error should call out the empty bucket name: {err}"
    );
}

/// `inbox` is reserved as a bucket name, because the writer allow-list lookup
/// short-circuits on it.
///
/// `writer_allowlist_for` returns `[ingest].inbox_allowed_writer_fingerprints` for any
/// channel named `inbox`, before consulting the buckets, so a bucket with that name inherits
/// the local inbox's allow-list. Under `writer_policy = "enforce"` a package from that
/// provider signed by the local key is admitted while a legitimately-signed provider package
/// is quarantined: cross-channel trust bleed, which is what a per-channel allow-list exists
/// to prevent. `is_valid_channel_name` accepts `inbox`, since it is a valid suppression
/// channel, so the reservation is asserted where bucket names are minted.
#[test]
#[serial(env)]
fn preflight_rejects_inbox_as_an_s3_bucket_name() {
    let toml = minimal_toml("")
        + r#"
[[s3.buckets]]
name = "inbox"
"#;
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(
        err.to_string().contains("reserved"),
        "the error must name the reservation, not a generic grammar failure: {err}"
    );
    // A name that merely contains `inbox` must not trip the reservation. It still fails
    // preflight here, because this fixture gives no endpoint, but for a different reason —
    // the discrimination worth pinning, since a `contains`-based check would be a silent
    // over-reach that renames a legitimate bucket out from under an operator.
    let near = minimal_toml("")
        + r#"
[[s3.buckets]]
name = "inbox-eu"
"#;
    let near_err = ServiceConfig::from_toml_str(&near)
        .unwrap()
        .preflight()
        .unwrap_err();
    assert!(
        !near_err.to_string().contains("reserved"),
        "only the exact name `inbox` is reserved; got: {near_err}"
    );
    // ...and name the different reason. A bare `!contains("reserved")` is satisfied by any
    // other failure at all, including one where the reservation check silently stopped
    // running and this bucket was rejected for something unrelated. Only a positive
    // assertion pins the discrimination.
    assert!(
        near_err
            .to_string()
            .contains("missing a non-empty endpoint"),
        "the near-miss must fail for the FIXTURE's reason (no endpoint), which is what \
         makes it evidence that the reservation did not fire: {near_err}"
    );
}

/// A bucket `name` preflight accepts must be usable as a suppression channel.
///
/// `name` is the channel key: `channel hide` / `channel take-down` write
/// `channel-<name>.json` through `suppression::channel_file_path`, which enforces a grammar
/// (at most 128 bytes, not `.`/`..`, no `/`, `\\` or NUL). Without this check `name =
/// "utartu/prod"` boots green — a slash in a human-facing logical name is unremarkable, and
/// the same string is also a Prometheus label and a Vault KV path component, neither of
/// which forbids it — and then fails inside `channel_file_path` at the moment an operator
/// reaches for a take-down: no `channel-*.json` written, no dataset withheld. Rejecting at
/// boot moves that failure to a moment when nothing is on fire.
#[test]
#[serial(env)]
fn preflight_rejects_an_s3_bucket_name_unusable_as_a_channel() {
    let toml = minimal_toml("")
        + r#"
[[s3.buckets]]
name = "utartu/prod"
"#;
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(
        err.to_string().contains("utartu/prod"),
        "error should name the offending bucket: {err}"
    );
}

/// `[fairdp]` IRI-safety and taxonomy validation: a theme outside the configured
/// `theme_taxonomy`, or with no shared derivable scheme when the override is absent, is
/// rejected; a malformed `license` IRI is rejected; and because a config IRI is served
/// verbatim in the FDP RDF, the scheme allow-list applies to `theme`, `publisher.mbox` and
/// `contact_point.has_url` alike.
#[test]
#[serial(env)]
fn preflight_validates_fairdp_iri_and_taxonomy_fields() {
    let cases: [(&str, String, Expect); 11] = [
        (
            "theme_not_in_taxonomy",
            fairdp_toml(
                r#"theme_taxonomy = "http://publications.europa.eu/resource/authority/other-vocab""#,
            ),
            Expect::Fail("theme_taxonomy"),
        ),
        (
            "theme_in_taxonomy_accepted",
            fairdp_toml(
                r#"theme_taxonomy = "http://publications.europa.eu/resource/authority/data-theme""#,
            ),
            Expect::Pass,
        ),
        (
            "themes_without_shared_scheme",
            fairdp_toml("").replace(
                r#"theme = ["http://publications.europa.eu/resource/authority/data-theme/HEAL"]"#,
                r#"theme = ["http://publications.europa.eu/resource/authority/data-theme/HEAL", "http://example.org/other-scheme/X"]"#,
            ),
            Expect::Fail("scheme"),
        ),
        (
            "bad_fairdp_license_iri",
            fairdp_toml("").replace(
                r#"license = "https://creativecommons.org/licenses/by/4.0/""#,
                r#"license = "not a url""#,
            ),
            Expect::Fail("fairdp.license"),
        ),
        (
            "mbox_javascript_scheme_rejected",
            fairdp_toml("").replace(
                "name = \"University of Tartu\"",
                "name = \"University of Tartu\"\nmbox = \"javascript:alert(1)\"",
            ),
            Expect::Fail("fairdp.publisher.mbox"),
        ),
        (
            // A valid mailto: mbox alongside an https homepage still preflights.
            "mbox_valid_mailto_accepted",
            fairdp_toml("").replace(
                "name = \"University of Tartu\"",
                "name = \"University of Tartu\"\nhomepage = \"https://gdi.ut.ee\"\nmbox = \"mailto:gdi@example.org\"",
            ),
            Expect::Pass,
        ),
        (
            // `vcard:hasURL` is emitted as an IRI too, so it gets the scheme allow-list.
            "contact_has_url_javascript_scheme_rejected",
            fairdp_toml("").replace(
                "has_email = \"mailto:gdi@example.org\"",
                "has_email = \"mailto:gdi@example.org\"\nhas_url = \"javascript:alert(1)\"",
            ),
            Expect::Fail("has_url"),
        ),
        (
            "theme_javascript_scheme_rejected",
            fairdp_toml("").replace(
                r#"theme = ["http://publications.europa.eu/resource/authority/data-theme/HEAL"]"#,
                r#"theme = ["javascript:alert(1)"]"#,
            ),
            Expect::Fail("fairdp.theme"),
        ),
        (
            "theme_data_scheme_rejected",
            fairdp_toml("").replace(
                r#"theme = ["http://publications.europa.eu/resource/authority/data-theme/HEAL"]"#,
                r#"theme = ["data:text/plain,hello"]"#,
            ),
            Expect::Fail("fairdp.theme"),
        ),
        (
            // A theme IRI with an opaque path (no `/` at all, e.g. a `urn:`) passes the
            // IRI/scheme check but has no derivable SKOS scheme (no parent path) — a
            // distinct failure from "themes disagree on scheme".
            "theme_no_derivable_scheme",
            fairdp_toml("").replace(
                r#"theme = ["http://publications.europa.eu/resource/authority/data-theme/HEAL"]"#,
                r#"theme = ["urn:isbn:0451450523"]"#,
            ),
            Expect::Fail("derivable"),
        ),
        (
            // Two themes that do share one derived scheme (no theme_taxonomy override)
            // preflight cleanly — the multi-theme sibling of `theme_in_taxonomy_accepted`.
            "themes_sharing_derived_scheme_accepted",
            fairdp_toml("").replace(
                r#"theme = ["http://publications.europa.eu/resource/authority/data-theme/HEAL"]"#,
                r#"theme = ["http://publications.europa.eu/resource/authority/data-theme/HEAL", "http://publications.europa.eu/resource/authority/data-theme/GENOMICS"]"#,
            ),
            Expect::Pass,
        ),
    ];
    for (label, toml, expect) in cases {
        assert_preflight_case(label, &toml, &expect);
    }
}

/// `[service]` socket-address and `data_dir` validation. Each row is a full
/// `[service]`-only TOML that must either preflight cleanly or fail with
/// `InvalidConfig` (optionally naming a substring of the message — an empty needle
/// means the original scenario only pinned the error class).
#[test]
#[serial(env)]
fn preflight_validates_service_socket_and_data_dir_fields() {
    let cases = [
        (
            "empty_base_url",
            r#"
[service]
base_url = ""
data_dir = "/data"
"#,
            Expect::Fail("service.base_url is required"),
        ),
        (
            "malformed_base_url",
            r#"
[service]
base_url = "not a url"
data_dir = "/data"
"#,
            Expect::Fail("base_url"),
        ),
        (
            "request_timeout_over_shutdown_drain",
            r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"
request_timeout_seconds = 60
shutdown_drain_seconds = 30

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#,
            Expect::Fail("must not exceed service.shutdown_drain_seconds"),
        ),
        (
            "management_addr_equal_listen",
            r#"
[service]
listen = "0.0.0.0:8080"
base_url = "https://gdi-ee.example.org"
data_dir = "/data"
management_addr = "0.0.0.0:8080"
"#,
            Expect::Fail("must not equal service.listen"),
        ),
        (
            "empty_management_addr",
            r#"
[service]
listen = "0.0.0.0:8080"
base_url = "https://gdi-ee.example.org"
data_dir = "/data"
management_addr = ""
"#,
            Expect::Fail("service.management_addr is required"),
        ),
        (
            // A non-socket-address `listen` must fail preflight, not crash-loop later at
            // `TcpListener::bind`.
            "malformed_listen",
            r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"
listen = "not-an-address"
"#,
            Expect::Fail("service.listen"),
        ),
        (
            "management_addr_that_is_not_a_socket_addr",
            r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"
listen = "0.0.0.0:8080"
management_addr = "localhost:9090"
"#,
            Expect::Fail("service.management_addr"),
        ),
        (
            // `[::]:PORT` is the other shipped form and must parse as a socket address.
            "ipv6_bracketed_listen_accepted",
            r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"
listen = "[::]:8080"
management_addr = "[::]:9090"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#,
            Expect::Pass,
        ),
        (
            // `data_dir` defaults to an empty PathBuf; omitting it must fail at
            // preflight instead of late at `create_dir_all("")`.
            "unset_data_dir",
            r#"
[service]
base_url = "https://gdi-ee.example.org"
"#,
            Expect::Fail("service.data_dir"),
        ),
        (
            // A relative `data_dir` would silently root the data tree under the process
            // working directory (`/` under systemd); reject it.
            "relative_data_dir",
            r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "relative/datasets"
"#,
            Expect::Fail("service.data_dir"),
        ),
    ];
    for (label, toml, expect) in cases {
        assert_preflight_case(label, toml, &expect);
    }
}

/// `[beacon.configuration]` closed-enum validation: bad values are rejected, and
/// non-default in-set values (e.g. a registered-tier dev node) are accepted.
#[test]
#[serial(env)]
fn preflight_validates_beacon_configuration_enums() {
    // Each of the three closed GA4GH beacon enum fields is rejected when its value
    // is outside the allowed set (a typo would otherwise serve a non-conformant
    // `/info` / `/configuration` response).
    for (field, line) in [
        ("default_granularity", r#"default_granularity = "RECORD""#),
        ("production_status", r#"production_status = "prod""#),
        ("security_level", r#"security_level = "public""#),
    ] {
        let toml = format!(
            r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"

[beacon.configuration]
{line}
"#
        );
        let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
        let err = cfg.preflight().unwrap_err();
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
        assert!(
            err.to_string().contains(field),
            "error for {field} should name the field: {err}"
        );
    }

    // Non-default but in-set values are accepted (e.g. a registered-tier dev node).
    let cfg = ServiceConfig::from_toml_str(
        r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"

[beacon.configuration]
default_granularity = "count"
production_status = "DEV"
security_level = "REGISTERED"
"#,
    )
    .unwrap();
    cfg.preflight().unwrap();
}

#[test]
#[serial(env)]
fn s3_buckets_parse_with_defaults_and_overrides() {
    let cfg = ServiceConfig::from_toml_str(
        r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"

[[s3.buckets]]
name = "primary"
endpoint = "https://s3.example.org"
bucket = "gdi-ee"
path_style = true
access_key_id = "AKIA"
secret_access_key = "secret"

[[s3.buckets]]
name = "local-garage"
endpoint = "http://127.0.0.1:3900"
bucket = "datasets"
region = "garage"
path_style = true
allow_http = true
marker_poll_interval = 5
full_poll_interval = 60
write_status = true
"#,
    )
    .unwrap();
    assert!(cfg.has_s3_buckets());
    let buckets = &cfg.s3.as_ref().unwrap().buckets;
    assert_eq!(buckets.len(), 2);

    // First bucket: explicit creds, defaulted intervals + flags.
    let primary = &buckets[0];
    assert_eq!(primary.name, "primary");
    assert_eq!(primary.endpoint.as_deref(), Some("https://s3.example.org"));
    assert_eq!(primary.bucket.as_deref(), Some("gdi-ee"));
    assert!(primary.path_style);
    assert!(!primary.allow_http);
    assert_eq!(primary.access_key_id.as_deref(), Some("AKIA"));
    assert_eq!(primary.secret_access_key.as_deref(), Some("secret"));
    assert_eq!(primary.region, None);
    assert_eq!(primary.marker_poll_interval, 30);
    assert_eq!(primary.full_poll_interval, 300);
    assert!(!primary.write_status);

    // Second bucket: explicit intervals, allow_http, write_status, region.
    let garage = &buckets[1];
    assert_eq!(garage.name, "local-garage");
    assert!(garage.allow_http);
    assert_eq!(garage.region.as_deref(), Some("garage"));
    assert_eq!(garage.marker_poll_interval, 5);
    assert_eq!(garage.full_poll_interval, 60);
    assert!(garage.write_status);

    cfg.preflight().unwrap();
}

#[test]
#[serial(env)]
fn vault_config_parses_with_defaults() {
    let cfg = ServiceConfig::from_toml_str(
        r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"

[vault]
address = "https://vault.example.org"
token = "hvs.EXAMPLE"
kv_path = "gdi-node-standalone/c4gh-identities"
s3_path = "gdi-node-standalone/s3-credentials"
"#,
    )
    .unwrap();
    assert!(cfg.has_vault());
    let vault = cfg.vault.as_ref().unwrap();
    assert_eq!(vault.address, "https://vault.example.org");
    assert_eq!(vault.token.as_deref(), Some("hvs.EXAMPLE"));
    assert_eq!(
        vault.kv_path.as_deref(),
        Some("gdi-node-standalone/c4gh-identities")
    );
    assert_eq!(
        vault.s3_path.as_deref(),
        Some("gdi-node-standalone/s3-credentials")
    );
    // Defaults applied for omitted mounts.
    assert_eq!(vault.kv_mount, "secret");
    assert_eq!(vault.transit_mount, "transit");
    assert!(vault.transit_key.is_none());
    assert!(!cfg.has_transit_key());
    assert!(vault.role_id.is_none());
    assert!(vault.secret_id.is_none());
}

#[test]
#[serial(env)]
fn vault_config_parses_approle_and_transit() {
    let cfg = ServiceConfig::from_toml_str(
        r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"

[vault]
address = "https://vault.example.org"
namespace = "admin/gdi"
role_id = "role-123"
secret_id = "secret-456"
kv_mount = "gdi-kv"
kv_path = "node/identities"
transit_mount = "gdi-transit"
transit_key = "gdi-node-standalone-at-rest"
"#,
    )
    .unwrap();
    let vault = cfg.vault.as_ref().unwrap();
    assert_eq!(vault.namespace.as_deref(), Some("admin/gdi"));
    assert_eq!(vault.role_id.as_deref(), Some("role-123"));
    assert_eq!(vault.secret_id.as_deref(), Some("secret-456"));
    assert_eq!(vault.kv_mount, "gdi-kv");
    assert_eq!(vault.transit_mount, "gdi-transit");
    assert_eq!(
        vault.transit_key.as_deref(),
        Some("gdi-node-standalone-at-rest")
    );
    assert!(cfg.has_transit_key());
    assert!(vault.token.is_none());
}

/// `VaultConfig::kv_mount`/`transit_mount` fall back to their documented defaults
/// (`secret`/`transit`) when the field is unset/empty — an explicit empty string in
/// TOML (`kv_mount = ""`) must resolve the same as omitting it, not resolve to an
/// empty Vault path. These accessors (not the raw fields) are what the Vault client
/// and rotation/identity CLIs actually consult.
#[test]
fn vault_config_kv_and_transit_mount_accessors_default_when_empty() {
    let mut vault = VaultConfig::default();
    assert_eq!(vault.kv_mount(), "secret");
    assert_eq!(vault.transit_mount(), "transit");

    vault.kv_mount = String::new();
    vault.transit_mount = String::new();
    assert_eq!(vault.kv_mount(), "secret");
    assert_eq!(vault.transit_mount(), "transit");

    vault.kv_mount = "custom-kv".to_owned();
    vault.transit_mount = "custom-transit".to_owned();
    assert_eq!(vault.kv_mount(), "custom-kv");
    assert_eq!(vault.transit_mount(), "custom-transit");
}

/// Disabling the audit trail must be an announced startup decision, like its siblings.
#[test]
fn audit_disabled_is_a_startup_advisory() {
    use crate::config::service::audit_disabled_warning;
    // The default posture says nothing.
    assert!(audit_disabled_warning(true).is_none());
    let msg = audit_disabled_warning(false).expect("a disabled audit trail must be announced");
    assert!(
        msg.contains("[audit].enabled"),
        "name the field an operator would set: {msg}"
    );
    assert!(
        msg.contains("DISABLED"),
        "state the posture plainly, as the k-anonymity advisory does: {msg}"
    );
}

/// The config's contact-point email must enforce the same cap as the package validator.
///
/// `check_contact_point` delegates to `validate_pkg::is_mailto_email` and the shared
/// 254-char cap, two lines from where `has_email` already calls into that module for the
/// IRI-character half. A local copy of the rule would drop the cap.
#[test]
#[serial(env)]
fn contact_point_email_is_bounded_like_every_other_email() {
    // 254 is the cap; build a valid-shaped mailto comfortably past it.
    let long_local = "a".repeat(300);
    let toml = fairdp_toml("").replace(
        r#"has_email = "mailto:gdi@example.org""#,
        &format!(r#"has_email = "mailto:{long_local}@example.org""#),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = cfg
        .preflight()
        .expect_err("an oversized contact email must be rejected");
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(
        err.to_string().contains("has_email"),
        "must name the field: {err}"
    );

    // A normal address is unaffected.
    ServiceConfig::from_toml_str(&fairdp_toml(""))
        .unwrap()
        .preflight()
        .expect("an ordinary contact email must still pass");
}

/// Every `#[serde(skip_serializing)]` field must be sentinel-checked by hand.
///
/// Such a field is absent from the JSON `preflight_no_placeholders` walks, so it inherits
/// that scan's blind spot the moment it is added. This reads the config source and demands
/// a matching `check_no_placeholder` call per skipped field, so the next one fails here
/// rather than shipping a config whose placeholder reaches a live secret backend.
///
/// Scoped to an attribute and a call, neither of which prose can satisfy.
#[test]
fn skip_serializing_fields_are_all_placeholder_checked() {
    let src = include_str!("service.rs");
    let mut skipped = Vec::new();
    let mut pending = false;
    for line in src.lines() {
        let t = line.trim();
        // `skip_serializing_if` is a different attribute: the field is serialized when the
        // condition is false, so the walk sees it and no hand-check is owed.
        if t == "#[serde(skip_serializing)]" {
            pending = true;
        } else if pending
            && let Some(rest) = t.strip_prefix("pub ")
            && let Some((name, _)) = rest.split_once(':')
        {
            skipped.push(name.to_owned());
            pending = false;
        }
    }
    assert!(
        !skipped.is_empty(),
        "the scan found no skip_serializing fields — it has stopped matching the source"
    );
    for field in &skipped {
        assert!(
            src.contains(&format!(r#"check_no_placeholder("vault.{field}""#)),
            "`{field}` is #[serde(skip_serializing)], so the placeholder leaf walk cannot \
             see it. Add `check_no_placeholder(\"vault.{field}\", …)` to `preflight_vault`. \
             Found checks for: {skipped:?}"
        );
    }
}

/// The placeholder scan serializes `self` and walks string leaves, but both Vault
/// credentials carry `#[serde(skip_serializing)]` for defence in depth and are therefore
/// absent from that JSON — the two highest-consequence secrets in the config. A non-empty
/// check would not catch them either, since `<SET ME: …>` is non-empty, so
/// `preflight_vault` sentinel-checks both by hand.
#[test]
#[serial(env)]
fn preflight_rejects_a_placeholder_in_the_unserialized_vault_credentials() {
    // The blind spot itself: the sentinel really is invisible to the leaf walk.
    let cfg = ServiceConfig::from_toml_str(&vault_toml("")).unwrap();
    let json = serde_json::to_value(&cfg).unwrap();
    assert!(
        !serde_json::to_string(&json)
            .unwrap()
            .contains("hvs.EXAMPLE"),
        "the token must stay out of the serialized form: that is the point of \
         skip_serializing, and the reason the scan cannot see it"
    );

    // token
    let toml = vault_toml("").replace(
        r#"token = "hvs.EXAMPLE""#,
        r#"token = "<SET ME: the vault token>""#,
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(
        err.to_string().contains("vault.token"),
        "must name the field: {err}"
    );

    // secret_id (the AppRole half; token removed so the two are not mutually exclusive)
    let toml = vault_toml("role_id = \"role\"\nsecret_id = \"<SET ME: the approle secret id>\"")
        .replace("token = \"hvs.EXAMPLE\"\n", "");
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = cfg.preflight().unwrap_err();
    assert!(
        err.to_string().contains("vault.secret_id"),
        "must name the field: {err}"
    );
}

/// Build a service config with a `[vault]` block, injecting `extra` lines under
/// the `[vault]` table header. Base block is the preflight-passing minimum
/// (address + token + `kv_path`).
fn vault_toml(extra: &str) -> String {
    format!(
        r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"

[vault]
address = "https://vault.example.org"
token = "hvs.EXAMPLE"
kv_path = "gdi-node-standalone/c4gh-identities"
{extra}
"#
    )
}

/// `[vault]` preflight validation. Each row builds on `vault_toml` (address + token +
/// `kv_path`, plus a `[beacon]` block) and either passes or fails with `InvalidConfig`
/// naming a substring of the message.
///
/// `preflight_rejects_plaintext_vault_when_advertising_prod_status` stays a separate test:
/// it asserts a setup precondition these rows do not share.
#[test]
#[serial(env)]
fn preflight_validates_vault_block() {
    let cases: [(&str, String, Expect); 17] = [
        ("token_baseline_accepted", vault_toml(""), Expect::Pass),
        (
            // Replace the token line with AppRole creds.
            "approle_baseline_accepted",
            vault_toml("").replace(
                r#"token = "hvs.EXAMPLE""#,
                "role_id = \"role-123\"\nsecret_id = \"secret-456\"",
            ),
            Expect::Pass,
        ),
        (
            "missing_address",
            vault_toml("").replace(
                r#"address = "https://vault.example.org""#,
                r#"address = """#,
            ),
            Expect::Fail("vault.address"),
        ),
        (
            "bad_address",
            vault_toml("").replace(
                r#"address = "https://vault.example.org""#,
                r#"address = "not a url""#,
            ),
            Expect::Fail("vault.address"),
        ),
        (
            // A non-loopback http:// Vault address in a prod environment
            // ships the token / AppRole secret_id / Transit DEKs in cleartext.
            "plaintext_in_prod_rejected",
            vault_toml("").replace(
                r#"address = "https://vault.example.org""#,
                r#"address = "http://vault.example.org""#,
            ),
            Expect::Fail("https"),
        ),
        (
            // A loopback (same-host sidecar) plaintext Vault is not a MITM exposure.
            "loopback_plaintext_allowed",
            vault_toml("").replace(
                r#"address = "https://vault.example.org""#,
                r#"address = "http://127.0.0.1:8200""#,
            ),
            Expect::Pass,
        ),
        (
            // The check must compare the parsed (lowercased) scheme, not the raw
            // string — a valid uppercase-scheme URL is HTTPS.
            "uppercase_https_allowed",
            vault_toml("").replace(
                r#"address = "https://vault.example.org""#,
                r#"address = "HTTPS://vault.example.org""#,
            ),
            Expect::Pass,
        ),
        (
            // A coherent development node is exempt: environment = dev and
            // production_status = DEV (the compose stack uses this pair — see
            // compose/node.full.toml). Both must be non-production for the plaintext
            // exemption.
            "coherent_dev_allows_plaintext",
            vault_toml("")
                .replace(
                    r#"address = "https://vault.example.org""#,
                    r#"address = "http://openbao:8200""#,
                )
                .replace(
                    r#"name = "GDI Estonia Beacon""#,
                    "name = \"GDI Estonia Beacon\"\nenvironment = \"dev\"\n\n[beacon.configuration]\nproduction_status = \"DEV\"",
                ),
            Expect::Pass,
        ),
        (
            "missing_kv_path",
            vault_toml("").replace("kv_path = \"gdi-node-standalone/c4gh-identities\"\n", ""),
            Expect::Fail("vault.kv_path"),
        ),
        (
            "without_auth",
            vault_toml("").replace("token = \"hvs.EXAMPLE\"\n", ""),
            Expect::Fail("auth"),
        ),
        (
            // role_id without secret_id.
            "incomplete_approle",
            vault_toml("").replace(r#"token = "hvs.EXAMPLE""#, r#"role_id = "role-123""#),
            Expect::Fail("role_id"),
        ),
        (
            // A present-but-empty transit_key would silently disable PME
            // (plaintext at rest); preflight must reject it, not boot fail-open.
            "empty_transit_key",
            vault_toml("transit_key = \"\""),
            Expect::Fail("transit_key"),
        ),
        (
            // token_file alone is the agent-sidecar shape: the token comes from a
            // file an external agent refreshes, so no static credential is stored.
            "token_file_alone_accepted",
            vault_toml("").replace(
                r#"token = "hvs.EXAMPLE""#,
                r#"token_file = "/run/secrets/vault/token""#,
            ),
            Expect::Pass,
        ),
        (
            // Two credential sources that can disagree must be a loud config error,
            // not a silent precedence rule.
            "token_and_token_file_together",
            vault_toml(r#"token_file = "/run/secrets/vault/token""#),
            Expect::Fail("mutually exclusive"),
        ),
        (
            // The half-finished migration from AppRole to an agent sidecar: `token_file`
            // set, the old `role_id`/`secret_id` still exported. A pairwise token/token_file
            // check would miss this, and `resolve_auth`'s ordering would silently pick
            // `token_file` while the AppRole credentials looked live — the state the
            // exclusivity rule exists to reject.
            "token_file_and_approle_together",
            vault_toml("")
                .replace(
                    r#"token = "hvs.EXAMPLE""#,
                    r#"token_file = "/run/secrets/vault/token""#,
                )
                .replace(
                    "[vault]",
                    "[vault]\nrole_id = \"11111111-2222-3333-4444-555555555555\"\nsecret_id = \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"",
                ),
            Expect::Fail("mutually exclusive"),
        ),
        (
            // Even a leftover half of an AppRole beside token_file is ambiguous enough to
            // reject: the operator cannot tell which credential is in force.
            "token_file_and_orphan_role_id",
            vault_toml("")
                .replace(
                    r#"token = "hvs.EXAMPLE""#,
                    r#"token_file = "/run/secrets/vault/token""#,
                )
                .replace(
                    "[vault]",
                    "[vault]\nrole_id = \"11111111-2222-3333-4444-555555555555\"",
                ),
            Expect::Fail("mutually exclusive"),
        ),
        (
            // A relative path would resolve against the process working directory, which
            // differs between a systemd unit and a container — the same trap data_dir has.
            "relative_token_file",
            vault_toml("").replace(
                r#"token = "hvs.EXAMPLE""#,
                r#"token_file = "run/secrets/vault/token""#,
            ),
            Expect::Fail("absolute"),
        ),
    ];
    // Hermetic env: `preflight_vault` reads the bare `VAULT_TOKEN` env var as an auth
    // source, so clear the environment to keep the `without_auth` case deterministic
    // regardless of any ambient `VAULT_TOKEN` in the calling shell.
    figment::Jail::expect_with(|jail| {
        jail.clear_env();
        for (label, toml, expect) in cases {
            assert_preflight_case(label, &toml, &expect);
        }
        Ok(())
    });
}

/// `vault::resolve_auth` honours the conventional bare `VAULT_TOKEN` environment variable
/// as an auth fallback, so `preflight_vault` must accept a `[vault]` block authenticated
/// only that way rather than aborting boot or `check-config` for a config the runtime would
/// authenticate.
#[test]
#[serial(env)]
fn preflight_accepts_bare_vault_token_env() {
    // A `[vault]` block with address + kv_path but no `vault.token` and no AppRole.
    let toml = vault_toml("").replace("token = \"hvs.EXAMPLE\"\n", "");

    figment::Jail::expect_with(|jail| {
        jail.clear_env();
        jail.set_env("VAULT_TOKEN", "hvs.ENVONLY");
        let cfg = ServiceConfig::from_toml_str(&toml).expect("config must parse");
        cfg.preflight()
            .expect("a bare VAULT_TOKEN must satisfy vault-auth preflight");
        Ok(())
    });

    // With the env var cleared, the same token-less config still fails closed.
    figment::Jail::expect_with(|jail| {
        jail.clear_env();
        let cfg = ServiceConfig::from_toml_str(&toml).expect("config must parse");
        let err = cfg
            .preflight()
            .expect_err("no vault.token, no AppRole, and no VAULT_TOKEN must fail closed");
        assert!(
            err.to_string().contains("auth"),
            "expected the vault-auth error, got {err}"
        );
        Ok(())
    });
}

#[test]
#[serial(env)]
fn preflight_rejects_plaintext_vault_when_advertising_prod_status() {
    // The Vault https requirement must fire on production_status = PROD too, not only on
    // environment = prod. A node that advertises production while setting environment = dev,
    // which alone would exempt plaintext Vault, must not silently ship the token, AppRole
    // secret_id or Transit DEKs in cleartext. That closes the gap where one
    // silently-overridable string downgrades a hard control.
    let toml = vault_toml("")
        .replace(
            r#"address = "https://vault.example.org""#,
            r#"address = "http://vault.example.org""#,
        )
        .replace(
            r#"name = "GDI Estonia Beacon""#,
            "name = \"GDI Estonia Beacon\"\nenvironment = \"dev\"",
        );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    // The setup is intentionally incoherent: env is dev, which a laxer gate would allow,
    // but the advertised production_status defaults to PROD.
    assert_eq!(cfg.beacon.environment, "dev");
    assert_eq!(cfg.beacon.configuration.production_status, "PROD");
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(err.to_string().contains("https"), "got: {err}");
}

#[test]
fn blocking_pool_pressure_warns_only_when_oversubscribed() {
    // Defaults (64 * 4 = 256) sit under tokio's 512 blocking pool -> no warning.
    assert!(super::service::blocking_pool_pressure_warning(64, 4).is_none());
    // Exactly at the pool (strictly-greater threshold) is still allowed.
    assert!(super::service::blocking_pool_pressure_warning(256, 2).is_none()); // == 512
    // Oversubscribed -> a warning naming both knobs.
    let msg = super::service::blocking_pool_pressure_warning(64, 16)
        .expect("64 * 16 = 1024 > 512 must warn");
    assert!(
        msg.contains("max_concurrent_requests") && msg.contains("ingest_concurrency"),
        "got: {msg}"
    );
}

/// The blocking-pool-pressure advisory is a warning, not a preflight failure. Unlike
/// `blocking_pool_pressure_warns_only_when_oversubscribed` above (which calls the
/// pure function directly), this exercises the actual `preflight` call site that
/// logs it, so an oversubscribed config must still preflight `Ok`.
#[test]
#[serial(env)]
fn preflight_warns_but_does_not_fail_on_blocking_pool_pressure() {
    let mut cfg = ServiceConfig::from_toml_str(&fairdp_toml("")).unwrap();
    cfg.service.max_concurrent_requests = 64;
    cfg.service.ingest_concurrency = 16; // 64 * 16 = 1024 > tokio's 512 blocking pool.
    cfg.preflight()
        .expect("blocking-pool pressure is advisory only, not a preflight failure");
}

/// A minimal `tracing::Subscriber` that records the formatted message of every
/// event emitted on the calling thread, mirroring `ingest::tests::SpanNameRecorder`
/// (which does the same for span names) so a test can assert a `tracing::warn!`
/// actually fired — and inspect its text — without pulling in `tracing-subscriber`
/// (core has no such dev-dep).
#[derive(Clone, Default)]
struct EventMessageRecorder(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl tracing::Subscriber for EventMessageRecorder {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct MessageVisitor(String);
        impl tracing::field::Visit for MessageVisitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        self.0.lock().unwrap().push(visitor.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Run `f` under an [`EventMessageRecorder`] and return every event message it
/// emitted, joined with `\n`, so a test can assert a `tracing::warn!` fired with a
/// given substring (not just that the surrounding call returned `Ok`).
fn capture_tracing_events(f: impl FnOnce()) -> String {
    let recorder = EventMessageRecorder::default();
    let messages = std::sync::Arc::clone(&recorder.0);
    tracing::subscriber::with_default(recorder, f);
    messages.lock().unwrap().join("\n")
}

/// An `http://` endpoint without `allow_http` must be rejected at preflight, naming
/// `allow_http`.
///
/// Otherwise the only feedback is `object_store`'s client-build failure — `Generic S3 error:
/// ... HTTP error: builder error`, with no network call, naming neither the scheme, TLS nor
/// the flag — while `check-config` exits 0 saying nothing. This is the local MinIO/Garage
/// case the project's own compose stacks hit.
#[test]
#[serial(env)]
fn preflight_rejects_http_endpoint_without_allow_http() {
    let base = minimal_toml("");
    let toml = format!(
        "{base}\n[[s3.buckets]]\nname = \"a\"\nbucket = \"b\"\nendpoint = \"http://127.0.0.1:9000\"\n"
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    let msg = err.to_string();
    assert!(
        msg.contains("allow_http"),
        "the error must name the flag that fixes it: {msg}"
    );
    assert!(
        msg.contains("http://127.0.0.1:9000"),
        "the error must name the offending endpoint: {msg}"
    );

    // Opting in makes the same config legal (it is an explicit choice, not an error).
    let allowed = format!(
        "{base}\n[[s3.buckets]]\nname = \"a\"\nbucket = \"b\"\nallow_http = true\nendpoint = \"http://127.0.0.1:9000\"\n"
    );
    ServiceConfig::from_toml_str(&allowed)
        .unwrap()
        .preflight()
        .expect("allow_http = true is a supported opt-in");

    // https:// needs no opt-in.
    let tls = format!(
        "{base}\n[[s3.buckets]]\nname = \"a\"\nbucket = \"b\"\nendpoint = \"https://s3.example.org\"\n"
    );
    ServiceConfig::from_toml_str(&tls)
        .unwrap()
        .preflight()
        .expect("an https endpoint must not require allow_http");
}

/// The `allow_http` prod/non-loopback warning, and the `host_is_loopback` helper it calls,
/// is exercised through three `endpoint` shapes the S3 `endpoint` field is
/// not otherwise validated against: a value that does not even parse as a URL (a
/// fail-safe non-loopback), an IPv6 loopback, and a URL with no host at all. None of
/// these affect the preflight outcome — `allow_http` is an explicit opt-in, not an
/// error — so each must still preflight `Ok`; and the warning itself must actually
/// fire for the two non-loopback shapes, and must not fire for the loopback-exempt
/// one (the very distinction `host_is_loopback` exists to make).
#[test]
#[serial(env)]
fn preflight_s3_allow_http_prod_warning_covers_host_is_loopback_shapes() {
    // The trailing line lands in the fixture's `[beacon]` table: this is a PROD node.
    let base = minimal_toml("") + "environment = \"prod\"\n";
    for (endpoint, should_warn) in [
        ("not a url", true),          // fails url::Url::parse -> fail-safe non-loopback.
        ("http://[::1]:9000", false), // IPv6 loopback -> exempt.
        ("mailto:ops@example.com", true), // parses, but has no host at all.
    ] {
        let toml = format!(
            "{base}\n[[s3.buckets]]\nname = \"a\"\nbucket = \"b\"\nallow_http = true\nendpoint = {endpoint:?}\n"
        );
        let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
        let log = capture_tracing_events(|| {
            cfg.preflight().unwrap_or_else(|e| {
                panic!("endpoint {endpoint:?}: allow_http is advisory only: {e}")
            });
        });
        assert_eq!(
            log.contains("allow_http (plaintext)"),
            should_warn,
            "endpoint {endpoint:?}: allow_http-in-prod warning fired={}, want {should_warn}: {log:?}",
            log.contains("allow_http (plaintext)")
        );
    }
}

/// `service.otlp_headers` carrying a secret over a plaintext non-loopback
/// `otlp_endpoint` in prod is likewise a warning (see `preflight_identity_and_otlp`), not
/// a preflight failure — the transport's URL validity is checked elsewhere
/// (`preflight_rejects_malformed_otlp_endpoint`); this only exercises the secret /
/// plaintext / prod / non-loopback warning branch, and asserts the warning itself
/// actually fired (not just that `preflight` returned `Ok`).
#[test]
#[serial(env)]
fn preflight_warns_on_plaintext_otlp_secret_headers_in_prod() {
    let mut cfg = ServiceConfig::from_toml_str(&fairdp_toml("")).unwrap();
    assert_eq!(cfg.beacon.environment, "prod");
    cfg.service.otlp_endpoint = Some("http://collector.example.org:4318".to_owned());
    let mut headers = std::collections::BTreeMap::new();
    headers.insert("Authorization".to_owned(), "ApiKey secret".to_owned());
    cfg.service.otlp_headers = Some(OtlpHeaders(headers));
    let log = capture_tracing_events(|| {
        cfg.preflight().expect(
            "a plaintext OTLP secret header in prod is advisory only, not a preflight failure",
        );
    });
    assert!(
        log.contains("otlp_headers carries a secret exported over plaintext"),
        "the plaintext-OTLP-secret-header warning must fire: {log:?}"
    );
}

#[test]
#[serial(env)]
fn vault_secrets_are_not_serialized() {
    // Defence in depth: the Vault token and AppRole secret_id must never appear in a
    // serialized config, so a config dump, echo or log line cannot leak them. The non-secret
    // `role_id` is the positive control: serialization is happening, so the secret's absence
    // is meaningful rather than an empty document.
    let cfg = ServiceConfig::from_toml_str(&vault_toml("")).unwrap();
    let json = serde_json::to_string(cfg.vault.as_ref().unwrap()).unwrap();
    assert!(!json.contains("hvs.EXAMPLE"), "vault token leaked: {json}");

    let toml = vault_toml("").replace(
        r#"token = "hvs.EXAMPLE""#,
        "role_id = \"role-1\"\nsecret_id = \"S3KRET-ID\"",
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    let json = serde_json::to_string(cfg.vault.as_ref().unwrap()).unwrap();
    assert!(!json.contains("S3KRET-ID"), "secret_id leaked: {json}");
    assert!(
        json.contains("role-1"),
        "role_id (non-secret) must still serialize: {json}"
    );
}

/// `deny_unknown_fields`: any unrecognized / misplaced key (top-level or inside a
/// known section) is a hard load error, so a typo can never silently fall back to a
/// default or disable a control (e.g. a misspelled `transit_keys` would otherwise
/// silently disable PME with a clean preflight and write sensitive parquet in
/// plaintext).
#[test]
#[serial(env)]
fn rejects_unknown_keys_at_load() {
    let cases: [(&str, String, &str); 2] = [
        ("top_level_typo", "typo_key = true\n".to_owned(), "typo_key"),
        (
            "vault_transit_keys_typo",
            vault_toml("transit_keys = \"gdi-node-at-rest\""),
            "transit_keys",
        ),
    ];
    for (label, toml, needle) in cases {
        match ServiceConfig::from_toml_str(&toml) {
            Ok(_) => panic!("case {label}: an unknown key must fail to load, not be dropped"),
            Err(err) => {
                let msg = err.to_string().to_lowercase();
                assert!(
                    msg.contains("unknown") || msg.contains(needle),
                    "case {label}: error should name the unknown field: {err}"
                );
            }
        }
    }
}

#[test]
#[serial(env)]
fn rejects_typoed_env_overlay_key_at_load() {
    // The env overlay (`GDI_NODE__SECTION__KEY`) is held to the same `deny_unknown_fields`
    // contract as the TOML file: a misspelled overlay key is a hard load error, never
    // silently dropped, which would let an operator think they set a knob via env while the
    // default stood. figment enforces this; the test pins it, mirroring
    // `rejects_unknown_keys_at_load` for the env path.
    figment::Jail::expect_with(|jail| {
        // A near-miss of the real `ingest_concurrency` knob, inside the known
        // `[service]` section (which is `deny_unknown_fields`).
        jail.set_env("GDI_NODE__SERVICE__INGEST_CONCURRENCYY", "8");
        let err = ServiceConfig::from_toml_str(
            r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"
"#,
        )
        .expect_err("a typo'd GDI_NODE__ overlay key must fail to load, not be dropped");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("unknown") || msg.contains("ingest_concurrencyy"),
            "error should name the unknown env key: {err}"
        );
        Ok(())
    });
}

#[test]
#[serial(env)]
fn vault_secret_id_and_token_env_override_file() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "config.toml",
            r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"

[vault]
address = "https://vault.example.org"
role_id = "role-123"
secret_id = "file-secret"
"#,
        )?;
        // GDI_NODE__VAULT__SECRET_ID and GDI_NODE__VAULT__TOKEN override the file.
        jail.set_env("GDI_NODE__VAULT__SECRET_ID", "env-secret");
        jail.set_env("GDI_NODE__VAULT__TOKEN", "env-token");
        let cfg = ServiceConfig::load(Some(Path::new("config.toml"))).unwrap();
        let vault = cfg.vault.as_ref().unwrap();
        assert_eq!(vault.secret_id.as_deref(), Some("env-secret"));
        assert_eq!(vault.token.as_deref(), Some("env-token"));
        Ok(())
    });
}

#[test]
#[serial(env)]
fn service_config_env_overrides_file() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "config.toml",
            r#"
[service]
base_url = "https://file.example.org"
data_dir = "/data"
ingest_concurrency = 2
"#,
        )?;
        jail.set_env("GDI_NODE__SERVICE__INGEST_CONCURRENCY", "8");
        let cfg = ServiceConfig::load(Some(Path::new("config.toml"))).unwrap();
        // Env wins over the file.
        assert_eq!(cfg.service.ingest_concurrency, 8);
        assert_eq!(cfg.service.base_url, "https://file.example.org");
        Ok(())
    });
}

#[test]
#[serial(env)]
fn service_config_load_missing_config_rules() {
    figment::Jail::expect_with(|jail| {
        // 1. No flag and no `$GDI_CONFIG` (a fresh jail starts with it unset): the absent
        //    default path stays lenient, since an env-only run is legitimate there, so
        //    `load` must not hard-fail. Run first, before any `set_env`.
        ServiceConfig::load(None).expect("default missing path must load leniently");

        // 2. An explicit `--config` path that does not exist: fail fast, naming the path,
        //    rather than silently loading empty and dying later on `base_url`. The explicit
        //    flag takes precedence over `$GDI_CONFIG`, so this is independent of it.
        let err = ServiceConfig::load(Some(Path::new("nope.toml"))).unwrap_err();
        assert!(
            err.to_string().contains("config file not found"),
            "explicit missing --config must hard-fail: {err}"
        );

        // 3. An empty `$GDI_CONFIG` means "unset", so it must stay lenient rather than
        //    hard-fail: a common container default is `GDI_CONFIG=`.
        jail.set_env("GDI_CONFIG", "");
        ServiceConfig::load(None).expect("empty GDI_CONFIG must load leniently");

        // 4. An explicit but missing `$GDI_CONFIG` path: same hard error as the flag.
        jail.set_env("GDI_CONFIG", "also-missing.toml");
        let err = ServiceConfig::load(None).unwrap_err();
        assert!(
            err.to_string().contains("config file not found"),
            "explicit missing $GDI_CONFIG must hard-fail: {err}"
        );
        Ok(())
    });
}

/// The secret-bearing config fields must never appear in a `Debug` render of
/// the struct (a future `debug!(?config)` / log line must not leak them).
/// Asserts both that the planted secret value is absent and that the field
/// names are still rendered (as a redacted placeholder), so the redaction is
/// scoped to the value, not the whole struct.
#[test]
fn debug_redacts_secret_fields() {
    const PLANTED_TOKEN: &str = "hvs.PLANTED-VAULT-TOKEN";
    const PLANTED_SECRET_ID: &str = "PLANTED-APPROLE-SECRET-ID";
    const PLANTED_S3_SECRET: &str = "PLANTED-S3-SECRET-ACCESS-KEY";

    // VaultConfig: token + secret_id are secret-bearing.
    let vault = VaultConfig {
        address: "https://vault.example.org".to_owned(),
        token: Some(PLANTED_TOKEN.to_owned()),
        role_id: Some("role-123".to_owned()),
        secret_id: Some(PLANTED_SECRET_ID.to_owned()),
        ..VaultConfig::default()
    };
    let rendered = format!("{vault:?}");
    assert!(
        !rendered.contains(PLANTED_TOKEN),
        "VaultConfig Debug leaked the token: {rendered}"
    );
    assert!(
        !rendered.contains(PLANTED_SECRET_ID),
        "VaultConfig Debug leaked the secret_id: {rendered}"
    );
    // Non-secret fields still render (the struct is not opaque).
    assert!(rendered.contains("vault.example.org"));
    assert!(rendered.contains("role-123"));

    // S3Bucket: secret_access_key is secret-bearing.
    let bucket = S3Bucket {
        name: "primary".to_owned(),
        access_key_id: Some("AKIA-NOT-SECRET".to_owned()),
        secret_access_key: Some(PLANTED_S3_SECRET.to_owned()),
        ..S3Bucket::default()
    };
    let rendered = format!("{bucket:?}");
    assert!(
        !rendered.contains(PLANTED_S3_SECRET),
        "S3Bucket Debug leaked the secret_access_key: {rendered}"
    );
    assert!(rendered.contains("primary"));
    assert!(rendered.contains("AKIA-NOT-SECRET"));

    // ProfileS3: secret_access_key is secret-bearing.
    let profile_s3 = ProfileS3 {
        bucket: Some("gdi-ee".to_owned()),
        access_key_id: Some("AKIA-NOT-SECRET".to_owned()),
        secret_access_key: Some(PLANTED_S3_SECRET.to_owned()),
        ..ProfileS3::default()
    };
    let rendered = format!("{profile_s3:?}");
    assert!(
        !rendered.contains(PLANTED_S3_SECRET),
        "ProfileS3 Debug leaked the secret_access_key: {rendered}"
    );
    assert!(rendered.contains("gdi-ee"));
    assert!(rendered.contains("AKIA-NOT-SECRET"));

    // The redaction placeholder is present (value redacted, not omitted).
    assert!(format!("{vault:?}").contains("\"***\""));
    assert!(format!("{bucket:?}").contains("\"***\""));
    assert!(format!("{profile_s3:?}").contains("\"***\""));

    // A wrapping ServiceConfig also keeps secrets out of its Debug.
    let cfg = ServiceConfig {
        vault: Some(vault),
        s3: Some(S3Config {
            buckets: vec![bucket],
        }),
        ..ServiceConfig::default()
    };
    let rendered = format!("{cfg:?}");
    assert!(!rendered.contains(PLANTED_TOKEN));
    assert!(!rendered.contains(PLANTED_SECRET_ID));
    assert!(!rendered.contains(PLANTED_S3_SECRET));
}

/// The service's default Parquet caps must equal the tool's frozen
/// [`ParquetCaps::default`](crate::validate_parquet::ParquetCaps::default): the
/// `gdi-dataset-tool` producer validates packages against the latter while the
/// service validates ingest/query against the former, so a silent desync of the
/// duplicated default literals (two structs in two files) would let the tool bless a
/// package the node then rejects — or the reverse. This pins the producer/consumer
/// agreement at the default; an operator raising a `[service]` cap only ever widens
/// what the node accepts, never narrows below what the tool produced.
#[test]
fn service_default_caps_match_tool_default() {
    assert_eq!(
        ServiceSection::default().parquet_caps(),
        crate::validate_parquet::ParquetCaps::default(),
    );
}

/// `parquet_caps()` must thread each operator-tunable `[service]` cap into the
/// `ParquetCaps` it derives, rather than falling back to `ParquetCaps::default()`. The
/// values here differ from both the `ServiceSection` default and the `ParquetCaps` default,
/// so a dropped field assignment (falling through to `..ParquetCaps::default()`) or a
/// `-> Default::default()` body is caught per cap.
#[test]
fn parquet_caps_carry_operator_byte_caps() {
    let section = ServiceSection {
        max_parquet_file_bytes: 111,
        max_parquet_decompressed_bytes: 222,
        max_parquet_row_group_bytes: 333,
        max_query_rows: 444,
        ..ServiceSection::default()
    };
    let caps = section.parquet_caps();
    assert_eq!(
        caps.max_parquet_file_bytes, 111,
        "file cap must thread through"
    );
    assert_eq!(
        caps.max_parquet_decompressed_bytes, 222,
        "decompressed cap must thread through"
    );
    assert_eq!(
        caps.max_parquet_row_group_bytes, 333,
        "row-group cap must thread through"
    );
    // The per-dataset query-row cap is operator-tunable too: it bounds serve-time memory
    // and the producer never reads it, so it is not part of the frozen producer/consumer
    // set the sibling `service_default_caps_match_tool_default` pins.
    assert_eq!(
        caps.max_query_rows, 444,
        "query-row cap must thread through"
    );
}

/// A minimal but valid `[service]` + `[beacon]` config with no `[s3]` block, so the
/// S3-bucket env-overlay tests below drive bucket creation purely from the env.
const S3_ENV_MINIMAL_TOML: &str = r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"
"#;

/// The documented "secrets without Vault" path: a bucket is defined in TOML with a
/// placeholder credential and `GDI_NODE__S3__BUCKETS__0__SECRET_ACCESS_KEY` injects the real
/// secret at load. figment cannot fold that numeric-keyed env dict into the `Vec<S3Bucket>`
/// field, since arrays are not index-merged, so `from_figment` pulls the bucket sub-overlay
/// out and applies it by index. This asserts the secret lands without clobbering the sibling
/// TOML fields, and that a typed (bool) field override parses.
#[test]
#[serial(env)]
fn s3_bucket_env_overlay_patches_inline_bucket() {
    figment::Jail::expect_with(|jail| {
        jail.set_env("GDI_NODE__S3__BUCKETS__0__SECRET_ACCESS_KEY", "real-secret");
        jail.set_env("GDI_NODE__S3__BUCKETS__0__PATH_STYLE", "true");
        let cfg = ServiceConfig::from_toml_str(
            r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"

[[s3.buckets]]
name = "primary"
endpoint = "https://s3.example.org"
bucket = "gdi-datasets"
access_key_id = "AKIAPLACEHOLDER"
"#,
        )
        .expect("config with an env-overlaid bucket secret must load");
        let s3 = cfg.s3.expect("[s3] present");
        let bucket = &s3.buckets[0];
        assert_eq!(bucket.name, "primary");
        assert_eq!(bucket.bucket.as_deref(), Some("gdi-datasets"));
        assert_eq!(bucket.access_key_id.as_deref(), Some("AKIAPLACEHOLDER"));
        assert_eq!(
            bucket.secret_access_key.as_deref(),
            Some("real-secret"),
            "the env override must inject the secret without clobbering the TOML fields"
        );
        assert!(
            bucket.path_style,
            "a typed (bool) field override must parse"
        );
        Ok(())
    });
}

/// Every `S3Bucket` field is env-settable — the probe that derives the field set must
/// serialise a key for each one.
///
/// The probe is a struct literal, so a new field is a compile error until it is listed. But
/// a field listed with an empty value is dropped by its `skip_serializing_if` and vanishes
/// from the set, after which the documented `GDI_NODE__S3__BUCKETS__<i>__…` override for it
/// is refused at boot as an unknown field — and nothing else notices. One listing serves both
/// halves here: the exhaustive destructure (no `..`) stops compiling when the struct grows,
/// and the same identifiers are the keys asserted, so the list cannot drift from the struct.
#[test]
fn the_s3_env_probe_exposes_every_bucket_field() {
    let probe = super::service::s3_bucket_env_probe();
    let serde_json::Value::Object(keys) = serde_json::to_value(&probe).unwrap() else {
        panic!("S3Bucket serialises to a JSON object")
    };
    macro_rules! fields {
        ($($field:ident),* $(,)?) => {{
            let S3Bucket { $($field: _),* } = &probe;
            [$(stringify!($field)),*]
        }};
    }
    for field in fields!(
        name,
        endpoint,
        bucket,
        prefix,
        region,
        path_style,
        allow_http,
        access_key_id,
        secret_access_key,
        marker_poll_interval,
        full_poll_interval,
        write_status,
        allowed_writer_fingerprints,
    ) {
        assert!(
            keys.contains_key(field),
            "`{field}` is missing from the env-overlay probe: its probe value is empty, so \
             `skip_serializing_if` dropped it and `GDI_NODE__S3__BUCKETS__<i>__{}` is refused \
             at boot as an unknown field",
            field.to_ascii_uppercase()
        );
    }
}

/// With no `[s3]` block at all, a full `GDI_NODE__S3__BUCKETS__0__*` env set materializes
/// the `[s3]` section and bucket 0 — the env-only credential path — with figment's
/// string-to-typed coercion honoured (`MARKER_POLL_INTERVAL` parses to `u64`) and untouched
/// fields keeping their defaults.
#[test]
#[serial(env)]
fn s3_bucket_env_overlay_creates_bucket_when_absent() {
    figment::Jail::expect_with(|jail| {
        jail.set_env("GDI_NODE__S3__BUCKETS__0__NAME", "primary");
        jail.set_env("GDI_NODE__S3__BUCKETS__0__BUCKET", "gdi-datasets");
        jail.set_env(
            "GDI_NODE__S3__BUCKETS__0__ENDPOINT",
            "https://s3.example.org",
        );
        jail.set_env("GDI_NODE__S3__BUCKETS__0__ACCESS_KEY_ID", "AKIA");
        jail.set_env("GDI_NODE__S3__BUCKETS__0__SECRET_ACCESS_KEY", "sekret");
        jail.set_env("GDI_NODE__S3__BUCKETS__0__MARKER_POLL_INTERVAL", "45");
        let cfg = ServiceConfig::from_toml_str(S3_ENV_MINIMAL_TOML)
            .expect("an env-only bucket must load");
        let s3 = cfg.s3.expect("[s3] materialized from the env overlay");
        assert_eq!(s3.buckets.len(), 1);
        let b = &s3.buckets[0];
        assert_eq!(b.name, "primary");
        assert_eq!(b.bucket.as_deref(), Some("gdi-datasets"));
        assert_eq!(b.endpoint.as_deref(), Some("https://s3.example.org"));
        assert_eq!(b.access_key_id.as_deref(), Some("AKIA"));
        assert_eq!(b.secret_access_key.as_deref(), Some("sekret"));
        assert_eq!(b.marker_poll_interval, 45);
        assert_eq!(
            b.full_poll_interval, 300,
            "untouched fields keep their defaults"
        );
        Ok(())
    });
}

/// A misspelled bucket field, or an override for a bucket index with no preceding bucket,
/// must each fail loudly rather than being silently dropped or surfacing as an opaque type
/// error.
#[test]
#[serial(env)]
fn s3_bucket_env_overlay_rejects_malformed_overrides() {
    for (label, env_key, env_val, needle) in [
        (
            "unknown_field",
            "GDI_NODE__S3__BUCKETS__0__ENDPOINT_TYPO",
            "x",
            "unknown S3 bucket field `endpoint_typo`",
        ),
        (
            "index_gap",
            "GDI_NODE__S3__BUCKETS__1__NAME",
            "orphan",
            "index 1 has no preceding bucket 0",
        ),
        // No `__<FIELD>` suffix at all after the index (just the prefix + index).
        (
            "malformed_key_no_field",
            "GDI_NODE__S3__BUCKETS__0",
            "x",
            "malformed S3 bucket env override",
        ),
        // The index segment itself does not parse as a non-negative integer.
        (
            "non_numeric_index",
            "GDI_NODE__S3__BUCKETS__abc__NAME",
            "x",
            "invalid S3 bucket index",
        ),
        // A bool-typed field given a non-bool value.
        (
            "bad_bool_value",
            "GDI_NODE__S3__BUCKETS__0__PATH_STYLE",
            "not-a-bool",
            "field `path_style` must be `true` or `false`",
        ),
        // A u64-typed field given a non-numeric value.
        (
            "bad_u64_value",
            "GDI_NODE__S3__BUCKETS__0__MARKER_POLL_INTERVAL",
            "not-a-number",
            "field `marker_poll_interval` must be a non-negative integer",
        ),
    ] {
        figment::Jail::expect_with(|jail| {
            jail.set_env(env_key, env_val);
            let err = ServiceConfig::from_toml_str(S3_ENV_MINIMAL_TOML).expect_err(&format!(
                "case {label}: must fail loudly, not be silently dropped"
            ));
            assert!(
                err.to_string().contains(needle),
                "case {label}: error should name {needle:?}: {err}"
            );
            Ok(())
        });
    }
}

/// A lower- or mixed-case `gdi_node__s3__buckets__…` override must still apply. The figment
/// env filter excludes bucket keys case-insensitively, and the hand-rolled overlay matches
/// the prefix case-insensitively too, so such a key is not dropped from both merge paths,
/// which would leave the bucket running with no credentials.
#[test]
#[serial(env)]
fn s3_bucket_env_overlay_matches_prefix_case_insensitively() {
    figment::Jail::expect_with(|jail| {
        jail.set_env("gdi_node__s3__buckets__0__name", "primary");
        jail.set_env("gdi_node__s3__buckets__0__path_style", "true");
        let cfg = ServiceConfig::from_toml_str(S3_ENV_MINIMAL_TOML)
            .expect("a lower-case bucket env override must load");
        let b = &cfg
            .s3
            .expect("[s3] materialized from the env overlay")
            .buckets[0];
        assert_eq!(b.name, "primary");
        assert!(
            b.path_style,
            "a lower-case override must apply, not be silently dropped"
        );
        Ok(())
    });
}

/// The env overlay is driven from the struct's serde impl, so a value must still coerce to
/// a typed (bool / u64) field and the change must round-trip cleanly.
#[test]
#[serial(env)]
fn s3_bucket_env_overlay_coerces_typed_fields_struct_driven() {
    figment::Jail::expect_with(|jail| {
        jail.set_env("GDI_NODE__S3__BUCKETS__0__NAME", "primary");
        jail.set_env("GDI_NODE__S3__BUCKETS__0__ALLOW_HTTP", "true");
        jail.set_env("GDI_NODE__S3__BUCKETS__0__FULL_POLL_INTERVAL", "900");
        let cfg = ServiceConfig::from_toml_str(S3_ENV_MINIMAL_TOML)
            .expect("typed env overrides must load");
        let b = &cfg.s3.expect("[s3] materialized").buckets[0];
        assert!(b.allow_http, "bool field must coerce from `true`");
        assert_eq!(b.full_poll_interval, 900, "u64 field must coerce");
        Ok(())
    });
}

/// `service.base_url` is emitted verbatim as the subject `<…>` IRI of every FDP record.
/// `url::Url::parse` accepts IRIREF-forbidden characters, percent-encoding them internally,
/// while `base_url` is stored and emitted raw, so preflight must reject them — otherwise a
/// `>` breaks out of the angle brackets and injects arbitrary triples.
#[test]
#[serial(env)]
fn preflight_rejects_iri_unsafe_base_url() {
    for bad in ["https://e.com/a>b", "https://e.com/x^y"] {
        let toml = format!(
            "[service]\nbase_url = \"{bad}\"\ndata_dir = \"/data\"\n\n\
             [beacon]\nid = \"ee.ut.af-beacon.production\"\nname = \"GDI Estonia Beacon\"\n"
        );
        let cfg =
            ServiceConfig::from_toml_str(&toml).expect("a base_url url::parse accepts must load");
        let err = cfg.preflight().unwrap_err();
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
        assert!(
            err.to_string().contains("not allowed in an IRI"),
            "unsafe base_url {bad:?} must hit the IRIREF guard: {err}"
        );
    }
}

#[test]
fn default_ingest_concurrency_is_raised_for_a_multi_provider_fleet() {
    // One node fronts many providers through one shared ingest pool, so too few workers let
    // a couple of slow packages starve every other provider. The default stays bounded, since
    // ingest is decrypt + parquet heavy: this is a throughput ceiling, not free parallelism.
    assert!(
        ServiceConfig::default().service.ingest_concurrency >= 4,
        "the fleet ingest default must leave room for more than a couple of providers"
    );
}

#[test]
fn duplicate_s3_bucket_names_are_rejected() {
    // Bucket `name` is the key for Vault-backed credentials, channel ownership and metric
    // labels, so two buckets sharing a name silently collide all three. With per-provider
    // buckets that is a plausible copy-paste slip among many entries, so preflight must
    // reject it rather than boot green with a hidden collision.
    let toml = r#"
[service]
base_url = "https://test.example.org"
data_dir = "/tmp/gdi-dup-test"

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "/beacon/v2"
id = "org.test.beacon"
name = "Test Beacon"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"

[[s3.buckets]]
name = "provider-a"
endpoint = "https://s3.example.org"
bucket = "bucket-1"

[[s3.buckets]]
name = "provider-a"
endpoint = "https://s3.example.org"
bucket = "bucket-2"
"#;
    let cfg = ServiceConfig::from_toml_str(toml).expect("config parses");
    let err = cfg
        .preflight()
        .expect_err("a duplicate [[s3.buckets]] name must fail preflight");
    let msg = err.to_string();
    assert!(
        msg.contains("duplicate") && msg.contains("provider-a"),
        "error must name the duplicate bucket: {msg}"
    );
}

#[test]
fn two_bucket_entries_addressing_one_keyspace_are_rejected() {
    // Distinct names, identical endpoint/bucket/prefix. Boot applies the same predicate the
    // reload does (`added_bucket_may_start`), so the two agree.
    //
    // What it costs: channel suppression is keyed by name. `channel take-down provider-a`
    // erases the dataset, then within `full_poll_interval` the twin lists the same
    // still-present object, does not match a suppression written for the other name, finds
    // no owner because the status row was just purged, and republishes it. The take-down is
    // permanently undone while `channel-provider-a.json` still reads as in force.
    let toml = r#"
[service]
base_url = "https://test.example.org"
data_dir = "/tmp/gdi-keyspace-test"

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "/beacon/v2"
id = "org.test.beacon"
name = "Test Beacon"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"

[[s3.buckets]]
name = "provider-a"
endpoint = "https://s3.example.org"
bucket = "shared-bucket"

[[s3.buckets]]
name = "provider-a-renamed"
endpoint = "https://s3.example.org"
bucket = "shared-bucket"
"#;
    let cfg = ServiceConfig::from_toml_str(toml).expect("config parses");
    let err = cfg
        .preflight()
        .expect_err("two entries on one keyspace must fail preflight");
    let msg = err.to_string();
    assert!(
        msg.contains("provider-a") && msg.contains("provider-a-renamed"),
        "the error must name BOTH channels so the operator can tell which to delete: {msg}"
    );

    // A differing prefix is a genuinely distinct keyspace and stays legal.
    let ok = toml.replace(
        "name = \"provider-a-renamed\"\nendpoint = \"https://s3.example.org\"\nbucket = \"shared-bucket\"",
        "name = \"provider-a-renamed\"\nendpoint = \"https://s3.example.org\"\nbucket = \"shared-bucket\"\nprefix = \"b/\"",
    );
    ServiceConfig::from_toml_str(&ok)
        .expect("config parses")
        .preflight()
        .expect("distinct prefixes are distinct keyspaces");
}

/// Two spellings that reach the wire as one keyspace are twins, not distinct entries.
///
/// `validate_key_prefix` accepts one optional trailing slash because the store wrapper
/// normalises it away, and `object_store` trims a trailing slash off the endpoint URL. So
/// `prefix = "a"` and `prefix = "a/"` — and an endpoint with or without its trailing slash —
/// list the same objects, which is the shape the twin check exists to refuse, because a
/// `channel take-down` of one is silently undone by the other. A comparison of the raw
/// strings would say they differ and let the pair boot.
#[test]
fn two_spellings_of_one_keyspace_are_rejected_as_twins() {
    let pair = |a: &str, b: &str| {
        let toml = minimal_toml("")
            + &format!(
                r#"
[[s3.buckets]]
name = "provider-a"
{a}

[[s3.buckets]]
name = "provider-b"
{b}
"#
            );
        ServiceConfig::from_toml_str(&toml)
            .expect("config parses")
            .preflight()
    };
    for (label, a, b) in [
        (
            "prefix with and without its trailing slash",
            "endpoint = \"https://s3.example.org\"\nbucket = \"gdi-datasets\"\nprefix = \"gdi-node-storage\"",
            "endpoint = \"https://s3.example.org\"\nbucket = \"gdi-datasets\"\nprefix = \"gdi-node-storage/\"",
        ),
        (
            "endpoint with and without its trailing slash",
            "endpoint = \"https://s3.example.org\"\nbucket = \"gdi-datasets\"",
            "endpoint = \"https://s3.example.org/\"\nbucket = \"gdi-datasets\"",
        ),
    ] {
        let err = pair(a, b).expect_err(label);
        assert_eq!(
            err.class(),
            crate::error::ErrorClass::InvalidConfig,
            "{label}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("same keyspace")
                && msg.contains("provider-a")
                && msg.contains("provider-b"),
            "{label}: the two spellings address one keyspace and must be refused as twins: {msg}"
        );
    }
}

#[test]
fn preflight_rejects_a_bucket_without_endpoint_or_bucket_name() {
    // `s3_conn::S3ConnParams` takes both as `&str`, so an entry missing either cannot build
    // a client at all. Without this check the service only logs a warning and drops the
    // bucket, which erases it from `/health/ready` — the rollup is `all(..)` over registered
    // channels, so an absent channel reads healthy — and the node serves nothing for that
    // provider while reporting ready.
    let base = r#"
[service]
base_url = "https://test.example.org"
data_dir = "/tmp/gdi-s3-required"

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "/beacon/v2"
id = "org.test.beacon"
name = "Test Beacon"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#;
    for (entry, missing) in [
        ("name = \"a\"\nbucket = \"b\"\n", "endpoint"),
        (
            "name = \"a\"\nendpoint = \"https://s3.example.org\"\n",
            "bucket",
        ),
        // Present-but-blank is the same defect with a friendlier-looking config file.
        (
            "name = \"a\"\nendpoint = \"   \"\nbucket = \"b\"\n",
            "endpoint",
        ),
    ] {
        let toml = format!("{base}\n[[s3.buckets]]\n{entry}");
        let cfg = ServiceConfig::from_toml_str(&toml).expect("config parses");
        let err = cfg
            .preflight()
            .expect_err("a bucket missing a required field must fail preflight")
            .to_string();
        assert!(
            err.contains(missing) && err.contains("\"a\""),
            "error must name the field and the bucket: {err}"
        );
    }

    // The complete form still passes.
    let ok = format!(
        "{base}\n[[s3.buckets]]\nname = \"a\"\nendpoint = \"https://s3.example.org\"\nbucket = \"b\"\n"
    );
    ServiceConfig::from_toml_str(&ok)
        .expect("config parses")
        .preflight()
        .expect("a fully specified bucket must pass preflight");
}

/// GA4GH `beaconInfoResults` requires `id`, `name` and the organization `id`/`name`; the
/// FDP publisher/HDAB `name`, and the FDP-root `title`/`issued`/`license`/
/// `applicable_legislation`, are likewise mandatory. All default to an empty string or list,
/// which the `<SET ME` placeholder scan does not catch, so a node that clears the sentinel
/// and leaves the field blank would advertise a nameless beacon or a SHACL-non-conformant
/// FDP record while `/health` stays green. Preflight must reject each empty required
/// identity field.
#[test]
#[serial(env)]
fn preflight_rejects_empty_required_identity_strings() {
    type Mutator = fn(&mut ServiceConfig);

    ServiceConfig::from_toml_str(&fairdp_toml(""))
        .unwrap()
        .preflight()
        .expect("base config must preflight");

    let cases: [(&str, Mutator); 8] = [
        ("beacon.id", |c| c.beacon.id.clear()),
        ("beacon.name", |c| c.beacon.name.clear()),
        ("fairdp.publisher.name", |c| {
            c.fairdp.as_mut().unwrap().publisher.name.clear();
        }),
        ("fairdp.hdab.name", |c| {
            c.fairdp.as_mut().unwrap().hdab.name.clear();
        }),
        ("fairdp.title", |c| c.fairdp.as_mut().unwrap().title.clear()),
        ("fairdp.issued", |c| {
            c.fairdp.as_mut().unwrap().issued.clear();
        }),
        ("fairdp.license", |c| {
            c.fairdp.as_mut().unwrap().license.clear();
        }),
        ("fairdp.applicable_legislation", |c| {
            c.fairdp.as_mut().unwrap().applicable_legislation.clear();
        }),
    ];
    for (field, mutate) in cases {
        let mut cfg = ServiceConfig::from_toml_str(&fairdp_toml("")).unwrap();
        mutate(&mut cfg);
        let err = cfg.preflight().unwrap_err();
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
        assert!(
            err.to_string().contains(field),
            "an empty {field} must be rejected naming it: {err}"
        );
    }
}

/// A set `service.otlp_endpoint` must be a well-formed URL (an unparseable value would
/// otherwise fail late, opaquely, inside the otel exporter). Parallel to the Vault/S3
/// endpoint guards.
#[test]
#[serial(env)]
fn preflight_rejects_malformed_otlp_endpoint() {
    let mut cfg = ServiceConfig::from_toml_str(&fairdp_toml("")).unwrap();
    cfg.service.otlp_endpoint = Some("not a url".to_owned());
    let err = cfg.preflight().unwrap_err();
    assert_eq!(err.class(), crate::error::ErrorClass::InvalidConfig);
    assert!(
        err.to_string().contains("otlp_endpoint"),
        "a malformed otlp_endpoint must be rejected naming it: {err}"
    );

    // A well-formed endpoint preflights.
    cfg.service.otlp_endpoint = Some("http://collector:4318".to_owned());
    cfg.preflight()
        .expect("a well-formed otlp_endpoint must preflight");
}

#[test]
fn writer_allowlist_is_per_channel_bucket_or_inbox() {
    // The trust boundary is the channel: the inbox list and each bucket list are distinct,
    // and an unknown channel has no list.
    let toml = r#"
[service]
base_url = "https://n.example.org/"
data_dir = "/var/lib/gdi/datasets"
inbox = "/var/lib/gdi/inbox"

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.n.beacon"
name = "N"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"

[ingest]
inbox_allowed_writer_fingerprints = ["sha256:inbox1"]

[[s3.buckets]]
name = "egv-bucket"
endpoint = "https://s3.example.org"
bucket = "egv"
allowed_writer_fingerprints = ["sha256:egv1", "sha256:egv2"]
"#;
    let cfg = ServiceConfig::from_toml_str(toml).expect("parses");
    assert_eq!(cfg.writer_allowlist_for("inbox"), ["sha256:inbox1"]);
    assert_eq!(
        cfg.writer_allowlist_for("egv-bucket"),
        ["sha256:egv1", "sha256:egv2"]
    );
    // An unknown channel (not the inbox, not a configured bucket) has no list.
    assert!(cfg.writer_allowlist_for("nope").is_empty());
}

/// The body both writer-policy fixtures share — an inbox node with one catalog — with
/// `keys` splicing in its `[keys]` block. Keeping it single-sourced makes the one
/// difference between the keyed and keyless nodes below the identity itself, not a
/// 20-line diff between two near-copies.
fn writer_policy_toml_with_keys(keys: &str, policy: &str, extra: &str) -> String {
    format!(
        r#"
[service]
base_url = "https://n.example.org/"
data_dir = "/var/lib/gdi/datasets"
inbox = "/var/lib/gdi/inbox"

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.n.beacon"
name = "N"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
{keys}
[ingest]
writer_policy = "{policy}"
{extra}
"#
    )
}

/// A node with a crypt4gh identity — the only coherent posture for `writer_policy`, which
/// gates crypt4gh writer keys. (A keyless node can decrypt nothing, so every artifact it
/// sees is an unidentified plaintext drop; `enforce` there would reject 100% of inputs and
/// is refused at preflight — see [`writer_policy_keyless_toml`].)
fn writer_policy_toml(policy: &str, extra: &str) -> String {
    writer_policy_toml_with_keys(
        r#"
[keys]
identities = ["/keys/node.c4gh"]
"#,
        policy,
        extra,
    )
}

/// The same node with no `[keys].identities` — a keyless, plaintext-only node.
fn writer_policy_keyless_toml(policy: &str, extra: &str) -> String {
    writer_policy_toml_with_keys("", policy, extra)
}

/// `enforce` gates crypt4gh writer keys, so it is incoherent on a node that holds no
/// identity: such a node cannot decrypt any `.tar.c4gh`, so every artifact reaching it is
/// an unidentified plaintext staging dir — which `enforce` quarantines. It would reject
/// everything, forever. Refuse it at preflight instead of booting a node that silently
/// serves nothing.
#[test]
fn enforce_on_a_keyless_node_refuses_to_boot() {
    let cfg = ServiceConfig::from_toml_str(&writer_policy_keyless_toml(
        "enforce",
        r#"inbox_allowed_writer_fingerprints = ["sha256:inbox1"]"#,
    ))
    .unwrap();
    let err = cfg
        .preflight()
        .expect_err("enforce on a keyless node must refuse to boot");
    assert!(
        err.to_string().contains("keys") && err.to_string().contains("enforce"),
        "the error must name the missing identity: {err}"
    );

    // Not waivable by the empty-allow-list ack: this is incoherence, not a posture.
    let acked = ServiceConfig::from_toml_str(&writer_policy_keyless_toml(
        "enforce",
        r#"allow_any_writer_ack = "we accept anything""#,
    ))
    .unwrap();
    acked
        .preflight()
        .expect_err("the ack must not waive a keyless enforce");
}

/// A keyless node is exactly the node that legitimately ingests plaintext, so `off` and
/// `warn` must still boot there — the keyless/co-located deployment must not be broken.
#[test]
fn off_and_warn_still_boot_on_a_keyless_node() {
    for policy in ["off", "warn"] {
        ServiceConfig::from_toml_str(&writer_policy_keyless_toml(policy, ""))
            .unwrap()
            .preflight()
            .unwrap_or_else(|e| panic!("{policy} must boot on a keyless node: {e}"));
    }
}

#[test]
fn enforce_with_an_empty_channel_allowlist_refuses_to_boot_without_ack() {
    // inbox is configured but has no allow-list -> enforce would reject every encrypted
    // package on it -> preflight fails, naming the channel.
    let cfg = ServiceConfig::from_toml_str(&writer_policy_toml("enforce", "")).unwrap();
    let err = cfg
        .preflight()
        .expect_err("enforce + empty list must refuse boot");
    assert!(
        err.to_string().contains("inbox") && err.to_string().contains("enforce"),
        "error names the offending channel: {err}"
    );
}

#[test]
fn enforce_boots_with_an_ack_or_with_a_populated_list() {
    // The explicit ack accepts the empty-list posture.
    let acked = ServiceConfig::from_toml_str(&writer_policy_toml(
        "enforce",
        r#"allow_any_writer_ack = "DPIA-2027-01: inbox is an internal trusted drop""#,
    ))
    .unwrap();
    acked.preflight().expect("ack lets enforce boot");

    // A populated inbox list also satisfies enforce (no ack needed).
    let listed = ServiceConfig::from_toml_str(&writer_policy_toml(
        "enforce",
        r#"inbox_allowed_writer_fingerprints = ["sha256:inbox1"]"#,
    ))
    .unwrap();
    listed
        .preflight()
        .expect("a populated list lets enforce boot");
}

#[test]
fn off_and_warn_never_refuse_boot_over_the_allowlist() {
    ServiceConfig::from_toml_str(&writer_policy_toml("off", ""))
        .unwrap()
        .preflight()
        .expect("off never gates");
    ServiceConfig::from_toml_str(&writer_policy_toml("warn", ""))
        .unwrap()
        .preflight()
        .expect("warn never refuses boot");
}

/// A minimal base config `Reloadable`/`changed_outside_reloadable_subset` tests build
/// on, carrying one catalog, one bucket, and an inbox allow-list entry.
fn reload_base_toml() -> &'static str {
    r#"
[service]
base_url = "https://n.example.org/"
data_dir = "/var/lib/gdi/datasets"
inbox = "/var/lib/gdi/inbox"

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.n.beacon"
name = "N"
environment = "test"
min_allele_count = 5

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"

[ingest]
writer_policy = "warn"
inbox_allowed_writer_fingerprints = ["sha256:inbox1"]

[[s3.buckets]]
name = "egv-bucket"
endpoint = "https://s3.example.org"
bucket = "egv"
allowed_writer_fingerprints = ["sha256:egv1"]
"#
}

#[test]
fn reloadable_extracts_catalogs_and_writer_allowlists_only() {
    let cfg = ServiceConfig::from_toml_str(reload_base_toml()).expect("parses");
    let reloadable = Reloadable::from_config(&cfg);

    assert_eq!(reloadable.catalogs.get("gdi-aggregated").unwrap(), "GoE");
    assert_eq!(reloadable.writer_policy, WriterPolicy::Warn);
    assert_eq!(reloadable.writer_allowlist_for("inbox"), ["sha256:inbox1"]);
    assert_eq!(
        reloadable.writer_allowlist_for("egv-bucket"),
        ["sha256:egv1"]
    );
    // A channel not present in this snapshot has no list — same "empty means no list"
    // contract as `ServiceConfig::writer_allowlist_for`.
    assert!(reloadable.writer_allowlist_for("unknown-bucket").is_empty());
}

#[test]
fn changed_outside_reloadable_subset_ignores_catalogs_and_allowlist_edits() {
    let old = ServiceConfig::from_toml_str(reload_base_toml()).expect("parses");
    let mut new = old.clone();
    // Add a catalog, flip the writer policy, extend both allow-lists and set the ack. Those
    // are every field the reloadable cell swaps, plus the ack, which preflight consults
    // transiently and never stores live, so none of them counts as a restart-worthy change.
    new.catalogs
        .insert("synthetic-data".to_owned(), "Synthetic".to_owned());
    new.ingest.writer_policy = WriterPolicy::Enforce;
    new.ingest.allow_any_writer_ack = "DPIA-2027-01".to_owned();
    new.ingest
        .inbox_allowed_writer_fingerprints
        .push("sha256:inbox2".to_owned());
    new.s3.as_mut().unwrap().buckets[0]
        .allowed_writer_fingerprints
        .push("sha256:egv2".to_owned());

    assert!(
        !old.changed_outside_reloadable_subset(&new),
        "editing only the reloadable subset must not be flagged as a restart-worthy change"
    );
}

#[test]
fn changed_outside_reloadable_subset_flags_a_restart_only_field() {
    let old = ServiceConfig::from_toml_str(reload_base_toml()).expect("parses");

    // The k-anonymity floor is explicitly restart-only (never reloadable — a live
    // lowering would re-expose suppressed counts).
    let mut min_allele_count_changed = old.clone();
    min_allele_count_changed.beacon.min_allele_count = 0;
    assert!(
        old.changed_outside_reloadable_subset(&min_allele_count_changed),
        "a changed min_allele_count must be flagged as restart-only"
    );

    // A listener address is likewise restart-only (a bound socket, captured at boot).
    let mut listen_changed = old.clone();
    listen_changed.service.listen = "0.0.0.0:9999".to_owned();
    assert!(
        old.changed_outside_reloadable_subset(&listen_changed),
        "a changed listen address must be flagged as restart-only"
    );

    // A rename is a removal plus an addition, and removal is the half that stays
    // restart-only, so the old name's monitor keeps running and this must flag.
    let mut bucket_renamed = old.clone();
    bucket_renamed.s3.as_mut().unwrap().buckets[0].name = "renamed-bucket".to_owned();
    assert!(
        old.changed_outside_reloadable_subset(&bucket_renamed),
        "a renamed bucket must be flagged as restart-only"
    );

    // Identical configs never spuriously flag.
    assert!(!old.changed_outside_reloadable_subset(&old.clone()));
}

/// A removed bucket keeps its writer allow-list, because its monitor keeps running.
///
/// Removal is restart-only, so the channel is still polling and still ingesting. Dropping its
/// allow-list would leave an empty one, and under `writer_policy = "enforce"` an empty list
/// admits nothing — so every package published to that bucket after the reload is quarantined
/// as `writer-rejected`, while the reload's own warning tells the operator removal changes
/// nothing until a restart. Fail-safe in direction, silent in operation, and contradicted by
/// what the operator was told.
#[test]
fn a_removed_channel_keeps_its_writer_allowlist_until_restart() {
    let mut previous = Reloadable::default();
    previous
        .per_channel_allowed_writer_fingerprints
        .insert("primary".to_owned(), vec!["sha256:aaa".to_owned()]);
    previous
        .per_channel_allowed_writer_fingerprints
        .insert("secondary".to_owned(), vec!["sha256:bbb".to_owned()]);

    // The reloaded file no longer declares `secondary`, and gives `primary` a new list.
    let mut reloaded = Reloadable::default();
    reloaded
        .per_channel_allowed_writer_fingerprints
        .insert("primary".to_owned(), vec!["sha256:ccc".to_owned()]);

    let merged = reloaded.retaining_removed_channels(&previous);
    assert_eq!(
        merged.writer_allowlist_for("primary"),
        ["sha256:ccc".to_owned()],
        "a channel the file still declares takes the RELOADED list, not the old one"
    );
    assert_eq!(
        merged.writer_allowlist_for("secondary"),
        ["sha256:bbb".to_owned()],
        "a removed channel keeps its list: its monitor is still running and still ingesting"
    );
}

/// The identity/access split itself, asserted on the predicate rather than through a reload.
///
/// Both directions matter and they fail differently. Calling an access field an identity one
/// only costs a needless restart. Calling an identity field an access one is the data-loss
/// path: the monitor is re-pointed at a keyspace that legitimately lists nothing, the
/// reconcile reads that as a mass deletion, and every dataset the channel owns is evicted and
/// deleted from disk while `/health/ready` still says `ok`.
#[test]
fn only_keyspace_fields_count_as_a_different_keyspace() {
    let base = S3Bucket {
        name: "primary".to_owned(),
        endpoint: Some("https://s3.example.org".to_owned()),
        bucket: Some("gdi-datasets".to_owned()),
        prefix: "node/".to_owned(),
        ..S3Bucket::default()
    };
    assert!(
        !base.addresses_different_keyspace_than(&base.clone()),
        "an unchanged descriptor addresses the same keyspace"
    );

    for (label, mutate) in [
        (
            "name",
            Box::new(|b: &mut S3Bucket| b.name = "renamed".to_owned())
                as Box<dyn Fn(&mut S3Bucket)>,
        ),
        (
            "endpoint",
            Box::new(|b: &mut S3Bucket| b.endpoint = Some("https://other.example.org".to_owned())),
        ),
        (
            "bucket",
            Box::new(|b: &mut S3Bucket| b.bucket = Some("other".to_owned())),
        ),
        (
            "prefix",
            Box::new(|b: &mut S3Bucket| b.prefix = "different/".to_owned()),
        ),
    ] {
        let mut changed = base.clone();
        mutate(&mut changed);
        assert!(
            base.addresses_different_keyspace_than(&changed),
            "{label} decides which objects the channel sees, so it is a keyspace change"
        );
    }

    for (label, mutate) in [
        (
            "credentials",
            Box::new(|b: &mut S3Bucket| {
                b.access_key_id = Some("AKIANEW".to_owned());
                b.secret_access_key = Some("rotated".to_owned());
            }) as Box<dyn Fn(&mut S3Bucket)>,
        ),
        (
            "region",
            Box::new(|b: &mut S3Bucket| b.region = Some("eu-north-1".to_owned())),
        ),
        (
            "path_style",
            Box::new(|b: &mut S3Bucket| b.path_style = !b.path_style),
        ),
        (
            "allow_http",
            Box::new(|b: &mut S3Bucket| b.allow_http = !b.allow_http),
        ),
        (
            "poll intervals",
            Box::new(|b: &mut S3Bucket| {
                b.marker_poll_interval = 11;
                b.full_poll_interval = 111;
            }),
        ),
        (
            "write_status",
            Box::new(|b: &mut S3Bucket| b.write_status = !b.write_status),
        ),
        (
            "allowed_writer_fingerprints",
            Box::new(|b: &mut S3Bucket| {
                b.allowed_writer_fingerprints = vec!["sha256:x".to_owned()];
            }),
        ),
    ] {
        let mut changed = base.clone();
        mutate(&mut changed);
        assert!(
            !base.addresses_different_keyspace_than(&changed),
            "{label} changes only how the channel reaches the same objects, so it hot-swaps"
        );
    }
}

/// The name-ignoring twin: a rename is the same keyspace under a new label.
///
/// The reload asks two different questions and one predicate cannot answer both. "Did this
/// channel's keyspace move?" includes `name`. "Is this newly-named entry the same keyspace a
/// still-running channel already polls?" must ignore it — otherwise every rename looks like a
/// fresh keyspace, and a rename starts a second monitor over one bucket while the old one
/// keeps polling, unremovable until a restart.
#[test]
fn the_name_ignoring_predicate_sees_a_rename_as_the_same_keyspace() {
    let base = S3Bucket {
        name: "primary".to_owned(),
        endpoint: Some("https://s3.example.org".to_owned()),
        bucket: Some("gdi-datasets".to_owned()),
        prefix: "node/".to_owned(),
        ..S3Bucket::default()
    };
    let renamed = S3Bucket {
        name: "renamed".to_owned(),
        ..base.clone()
    };
    assert!(
        base.addresses_different_keyspace_than(&renamed),
        "by name the two are different channels, which is what makes a rename restart-only"
    );
    assert!(
        !base.addresses_different_keyspace_than_ignoring_name(&renamed),
        "but they address one keyspace, which is why the second monitor must not start"
    );

    // A second channel on the same bucket under a different prefix stays distinct, so it is
    // still allowed to start — that posture is legitimate and must not be caught by this.
    let sibling = S3Bucket {
        name: "sibling".to_owned(),
        prefix: "other/".to_owned(),
        ..base.clone()
    };
    assert!(
        base.addresses_different_keyspace_than_ignoring_name(&sibling),
        "different prefixes are different keyspaces, even on one bucket"
    );
}

/// The keyspace identity is the wire spelling, so a trailing slash on `prefix` or `endpoint`
/// does not make a second keyspace.
///
/// Three surfaces read that identity and all three must agree: the reload's rename
/// detection (a rename that also tidies the slash is still the same keyspace, so a second
/// monitor must not start), the constructed witness (two spellings, one witness), and the
/// witness persisted beside the datasets — a file written by an earlier node version still
/// carries the slash, and the boot gate compares it with `==`, so equality itself has to
/// normalise or every such node reports a keyspace mismatch after a mere re-spelling.
#[test]
fn a_trailing_slash_does_not_change_the_keyspace_witness() {
    let spelled = |endpoint: &str, prefix: &str| S3Bucket {
        name: "primary".to_owned(),
        endpoint: Some(endpoint.to_owned()),
        bucket: Some("gdi-datasets".to_owned()),
        prefix: prefix.to_owned(),
        ..S3Bucket::default()
    };
    let bare = spelled("https://s3.example.org", "node");
    let mut slashed = spelled("https://s3.example.org/", "node/");
    slashed.name = "renamed".to_owned();

    assert!(
        !bare.addresses_different_keyspace_than_ignoring_name(&slashed),
        "a rename that only re-spells the slash is the same keyspace"
    );
    assert_eq!(
        bare.keyspace_witness(),
        slashed.keyspace_witness(),
        "two spellings of one keyspace must construct one witness"
    );
    let persisted = serde_json::to_string(&slashed.keyspace_witness()).unwrap();
    assert!(
        !persisted.contains("node/") && !persisted.contains("org/"),
        "the persisted witness carries the canonical (slash-free) spelling: {persisted}"
    );

    // A witness written before the constructor normalised.
    let legacy: KeyspaceWitness = serde_json::from_str(
        r#"{"endpoint":"https://s3.example.org/","bucket":"gdi-datasets","prefix":"node/"}"#,
    )
    .unwrap();
    assert_eq!(
        legacy,
        bare.keyspace_witness(),
        "an un-normalised witness on disk must still match the configured keyspace"
    );

    // Normalisation is a trailing-slash rule only: a different prefix stays different.
    assert_ne!(
        bare.keyspace_witness(),
        spelled("https://s3.example.org", "other").keyspace_witness()
    );
}

/// A bucket addition and a connection change are live-reloadable; a removal and a keyspace
/// change are not.
///
/// This asserts the distinction in both directions, because getting it wrong is silent
/// either way: flagging an applied change tells the operator to restart for something
/// already live, and not flagging a removal — or a re-pointed keyspace — tells them a bucket
/// was offboarded or moved while its monitor keeps polling and its datasets keep serving.
#[test]
fn changed_outside_reloadable_subset_separates_live_from_restart_only() {
    let old = ServiceConfig::from_toml_str(reload_base_toml()).expect("parses");

    // Modify, access/behaviour: the same objects reached with a new client, which is what
    // the monitor reload restarts for. A mistake in any of these fails loudly.
    for (label, mutate) in [
        (
            "rotated credential",
            Box::new(|b: &mut S3Bucket| {
                b.access_key_id = Some("AKIANEW".to_owned());
                b.secret_access_key = Some("rotated".to_owned());
            }) as Box<dyn Fn(&mut S3Bucket)>,
        ),
        (
            "write_status",
            Box::new(|b: &mut S3Bucket| b.write_status = true),
        ),
        (
            "poll interval",
            Box::new(|b: &mut S3Bucket| b.marker_poll_interval = 17),
        ),
    ] {
        let mut modified = old.clone();
        mutate(&mut modified.s3.as_mut().unwrap().buckets[0]);
        assert!(
            !old.changed_outside_reloadable_subset(&modified),
            "a modified bucket ({label}) is applied live by the monitor reload, so it \
             must not be reported as restart-only"
        );
    }

    // Modify, identity: a different keyspace. The monitor reload does not apply these, since
    // applying one live evicts every dataset the channel owns, so they are restart-only and
    // the operator must be told. Asserted per field: these three are the ones an operator
    // edits, and getting any of them wrong is silent.
    for (label, mutate) in [
        (
            "endpoint",
            Box::new(|b: &mut S3Bucket| {
                b.endpoint = Some("https://s3.other.example.org".to_owned());
            }) as Box<dyn Fn(&mut S3Bucket)>,
        ),
        (
            "bucket",
            Box::new(|b: &mut S3Bucket| b.bucket = Some("other-bucket".to_owned())),
        ),
        (
            "prefix",
            Box::new(|b: &mut S3Bucket| b.prefix = "gdi-node-storage/".to_owned()),
        ),
    ] {
        let mut modified = old.clone();
        mutate(&mut modified.s3.as_mut().unwrap().buckets[0]);
        assert!(
            old.changed_outside_reloadable_subset(&modified),
            "a changed {label} re-points the channel at a different keyspace, which is \
             restart-only — the operator must be told it was NOT applied"
        );
    }

    // Add: purely additive, and the reload starts a monitor for it.
    let mut added = old.clone();
    let mut second = old.s3.as_ref().unwrap().buckets[0].clone();
    second.name = "second-bucket".to_owned();
    added.s3.as_mut().unwrap().buckets.push(second.clone());
    assert!(
        !old.changed_outside_reloadable_subset(&added),
        "an added bucket is started by the monitor reload, so it must not be reported \
         as restart-only"
    );

    // Remove: the half that is not applied. The monitor keeps running against the old
    // descriptor until a restart, so the operator must be told.
    let mut removed = added.clone();
    removed.s3.as_mut().unwrap().buckets.remove(0);
    assert!(
        added.changed_outside_reloadable_subset(&removed),
        "a removed bucket stays restart-only and must be reported"
    );

    // Remove plus add in one reload: the same count as before, a different set. Counting
    // buckets instead of matching them by name would call this unchanged.
    let mut swapped = old.clone();
    swapped.s3.as_mut().unwrap().buckets[0] = second;
    assert!(
        old.changed_outside_reloadable_subset(&swapped),
        "swapping one bucket for another removes one, which stays restart-only"
    );

    // Reorder: no semantic change for a name-keyed set, so it must not be reported. The
    // comparison is `Debug`-string based and would otherwise see the reordering itself.
    let mut reordered = added.clone();
    reordered.s3.as_mut().unwrap().buckets.reverse();
    assert!(
        !added.changed_outside_reloadable_subset(&reordered),
        "reordering the bucket array changes nothing and must not be reported"
    );
}

#[test]
fn off_with_a_populated_allowlist_refuses_to_boot() {
    // A configured allow-list under `off` is silently inert — the list is ignored and every
    // writer is accepted — so an operator gets a false sense of gating. Refuse to boot.
    let err = ServiceConfig::from_toml_str(&writer_policy_toml(
        "off",
        r#"inbox_allowed_writer_fingerprints = ["sha256:inbox1"]"#,
    ))
    .unwrap()
    .preflight()
    .expect_err("off + a populated list must refuse boot");
    assert!(
        err.to_string().contains("inbox") && err.to_string().contains("off"),
        "error names the inert channel and the policy: {err}"
    );

    // `warn` is the intended discovery mode: a populated list is expected and boots.
    ServiceConfig::from_toml_str(&writer_policy_toml(
        "warn",
        r#"inbox_allowed_writer_fingerprints = ["sha256:inbox1"]"#,
    ))
    .unwrap()
    .preflight()
    .expect("warn + a populated list is the discovery mode and boots");
}

#[test]
fn management_addr_defaults_to_loopback() {
    // A config that omits `management_addr` binds loopback, not every interface, because the
    // plane carries the hidden-dataset oracle and metrics. `writer_policy_toml` sets no
    // `management_addr`, so this exercises the omitted-field default.
    let cfg = ServiceConfig::from_toml_str(&writer_policy_toml("off", "")).unwrap();
    assert_eq!(cfg.service.management_addr, "127.0.0.1:9090");
    cfg.preflight()
        .expect("loopback management_addr passes preflight (non-empty, != listen)");
}

#[test]
fn defaults_toml_renders_and_round_trips() {
    // `toml` refuses to emit a scalar after a table, so a struct whose field order
    // interleaves them serializes only by luck. Prove the real thing renders rather
    // than trusting that it compiles.
    let rendered = super::defaults_toml().expect("the default config must render as TOML");
    assert!(
        rendered.contains("rescan_interval_seconds"),
        "a known [service] scalar must be present: {rendered}"
    );

    // The point of a defaults dump is that it is the defaults: parsing it back must
    // reproduce `Default`, so an operator diffing against it compares like with like.
    // `deny_unknown_fields` also makes this a guard against emitting a key the parser would
    // reject.
    let reparsed = ServiceConfig::from_toml_str(&rendered)
        .expect("the rendered defaults must parse back through the real loader");
    let defaults = ServiceConfig::default();
    assert_eq!(
        reparsed.service.rescan_interval_seconds, defaults.service.rescan_interval_seconds,
        "round-trip must preserve scalars"
    );
    assert_eq!(
        reparsed.service.ingest_concurrency, defaults.service.ingest_concurrency,
        "round-trip must preserve scalars"
    );
    assert_eq!(
        reparsed.beacon.min_allele_count, defaults.beacon.min_allele_count,
        "round-trip must preserve nested-table scalars"
    );
}

/// The two traceparent-trust flags are independent.
///
/// Merged into one flag, an orchestrator wanting its S3 handoff correlated with the node's
/// ingest would also have to trust `traceparent` HTTP headers, on the public,
/// internet-facing Beacon, where the header is chosen by whoever reaches the port. Asserting
/// the recommended posture — sidecar on, headers off — pins the split.
#[test]
fn traceparent_trust_is_configurable_per_source() {
    let cfg = ServiceConfig::from_toml_str(
        r#"
[service]
base_url = "https://n.example.org"
data_dir = "/var/lib/gdi/datasets"
trust_sidecar_traceparent = true

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.n.beacon"
name = "N"
"#,
    )
    .expect("parses");
    assert!(
        cfg.service.trust_sidecar_traceparent,
        "the sidecar source is trusted on its own"
    );
    assert!(
        !cfg.service.trust_inbound_traceparent,
        "and that must not have turned on trust for inbound HTTP headers"
    );

    // ...and the reverse, so neither flag is merely the other one renamed.
    let cfg = ServiceConfig::from_toml_str(
        r#"
[service]
base_url = "https://n.example.org"
data_dir = "/var/lib/gdi/datasets"
trust_inbound_traceparent = true

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.n.beacon"
name = "N"
"#,
    )
    .expect("parses");
    assert!(cfg.service.trust_inbound_traceparent);
    assert!(!cfg.service.trust_sidecar_traceparent);
}

/// Both default to off, the posture every other trust flag in this file ships with.
#[test]
fn both_traceparent_trust_flags_default_off() {
    let default = ServiceConfig::default();
    assert!(!default.service.trust_inbound_traceparent);
    assert!(!default.service.trust_sidecar_traceparent);
}
