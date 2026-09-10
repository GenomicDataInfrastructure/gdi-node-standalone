use gdi_node_standalone_core::model::{Manifest, PackageYaml};

/// Every checked-in `docs/*.schema.json` equals the schema derived from its model, so a serde
/// change that alters a schema cannot leave the published file stale.
///
/// This pins the published type contract that the docs reference and consumers validate
/// against, where `manifest_json_round_trips` pins the wire shape. It loops over the whole
/// `schema::SCHEMAS` registry, so a new schema is covered without being listed here.
///
/// The `schema` feature is enabled only by the `test_schema` leg of `scripts/ci-local.sh`, so
/// removing that leg stops this guard running. Regenerate after an intended model change:
///   `GDI_BLESS_SCHEMA=1 cargo test -p gdi-node-standalone-core --features schema schema_files`
#[cfg(feature = "schema")]
#[test]
fn schema_files_match_the_models() {
    let bless = std::env::var_os("GDI_BLESS_SCHEMA").is_some();
    for (file, generate) in gdi_node_standalone_core::schema::SCHEMAS {
        let generated = generate();
        let path = format!("{}/../../docs/{file}", env!("CARGO_MANIFEST_DIR"));
        if bless {
            std::fs::write(&path, &generated).unwrap_or_else(|e| panic!("write docs/{file}: {e}"));
            continue;
        }
        let checked_in = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(
            generated, checked_in,
            "docs/{file} is stale vs its model — regenerate with \
             `GDI_BLESS_SCHEMA=1 cargo test -p gdi-node-standalone-core --features schema schema_files`"
        );
    }
}

#[test]
fn parse_example_manifest_json() {
    let raw = include_str!("../fixtures/manifest.json");
    let m: Manifest = serde_json::from_str(raw).expect("manifest parses");
    assert_eq!(m.metadata.dataset_id, "GDI-EE-UTARTU-20260409143052837");
    assert_eq!(m.config.assembly.reference, "GRCh38");
    assert_eq!(m.config.af_source.as_deref(), Some("The Genome of Europe"));
    assert_eq!(m.metadata.number_of_records, Some(123_456));
}

/// The wire fixture closes the five-term record identity the published schema states.
///
/// It carries a non-zero `recordsNoAf`, so an identity written over only four terms fails here
/// rather than closing on a zero.
#[test]
fn manifest_fixture_closes_the_record_identity_on_five_terms() {
    let raw = include_str!("../fixtures/manifest.json");
    let m: Manifest = serde_json::from_str(raw).expect("manifest parses");
    let stats = m.files[0].files[0]
        .conversion
        .as_ref()
        .expect("the fixture's VCF entry carries conversion stats");
    let d = &stats.discarded;
    assert!(
        d.records_no_af > 0,
        "the fixture must exercise the fifth term, or four terms close too"
    );
    let four = d.records_unsupported_contig
        + d.records_no_supported_alt
        + d.records_all_rows_withheld
        + stats.output.records_emitted;
    assert_eq!(
        stats.input.records,
        four + d.records_no_af,
        "the five-term identity must close on the fixture"
    );
    assert_ne!(
        stats.input.records, four,
        "the four-term identity must not close: `recordsNoAf` is a whole-record drop class"
    );
}

#[test]
fn parse_minimal_package_yaml() {
    let raw = include_str!("../fixtures/package.yaml");
    let p: PackageYaml = serde_saphyr::from_str(raw).expect("package.yaml parses");
    assert_eq!(p.metadata.prefix.as_deref(), Some("GDI"));
    assert_eq!(p.metadata.catalog, "gdi-aggregated");
    // First files group is the VCF group.
    assert_eq!(p.files[0].category, "VCF");
}

/// Serialize the parsed manifest fixture back to JSON, re-parse, and assert the
/// two `Manifest` values are equal. This locks the wire contract — the
/// `skip_serializing_if` / `rename_all = "camelCase"` / `fn` / `type` output —
/// so a future field rename or attribute change cannot silently break the
/// integration contract the node and any integrating system rely on.
#[test]
fn manifest_json_round_trips() {
    let raw = include_str!("../fixtures/manifest.json");
    let original: Manifest = serde_json::from_str(raw).expect("manifest parses");

    // Regeneration path, mirroring GDI_BLESS_SCHEMA: after an intended model change, rewrite
    // the fixture from the struct rather than hand-diffing two JSON values. This works only
    // for a backward-compatible change, since the old fixture must still parse. A breaking
    // change, such as a new required field, fails the parse above and must be re-authored.
    if std::env::var_os("GDI_BLESS_MANIFEST_FIXTURE").is_some() {
        let regenerated = serde_json::to_string_pretty(&original).expect("serialize manifest");
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/manifest.json");
        std::fs::write(path, format!("{regenerated}\n")).expect("write manifest fixture");
        return;
    }

    let serialized = serde_json::to_string(&original).expect("manifest serializes");
    let reparsed: Manifest = serde_json::from_str(&serialized).expect("re-parse");

    // Whole-struct equality (the strongest assertion) plus a few explicit
    // key-field checks that pin the camelCase / renamed tokens specifically.
    assert_eq!(original, reparsed);
    assert_eq!(
        reparsed.metadata.dataset_id,
        "GDI-EE-UTARTU-20260409143052837"
    );
    assert_eq!(reparsed.metadata.number_of_records, Some(123_456));
    assert_eq!(reparsed.config.assembly.reference, "GRCh38");
    assert_eq!(reparsed.config.manifest_version, 1);

    // The serialized form must use the camelCase / special tokens on the wire.
    assert!(serialized.contains("\"datasetId\""));
    assert!(serialized.contains("\"numberOfRecords\""));
    assert!(serialized.contains("\"manifestVersion\""));
    assert!(serialized.contains("\"hasEmail\""));
    assert!(serialized.contains("\"fn\""));

    // The `payload` section. It is `skip_serializing_if = "Option::is_none"`, so a fixture
    // without one pins only the payload-absent shape, and a rename or attribute change to
    // any of its three wire keys stays invisible: the field vanishes from both sides of the
    // comparison. The fixture must therefore carry a payload.
    let payload = reparsed.payload.as_ref().expect(
        "the fixture must carry a `payload` section — without one this test pins only the \
         absent shape and a rename of its wire keys stays invisible",
    );
    assert!(
        payload.algorithm_supported(),
        "the fixture must declare an algorithm this build can verify; ingest hard-rejects \
         anything else and `diff` silently downgrades to the weaker source basis"
    );
    assert_eq!(payload.members.len(), 2);
    let entry = payload
        .members
        .get("allele-freq.0000000000.parquet")
        .expect("payload.members is keyed by TAR member name");
    assert_eq!(entry.size, 1_048_576);
    assert_eq!(entry.sha256.len(), 64, "sha256 is 64 lowercase hex chars");
    assert!(
        entry
            .sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    assert!(serialized.contains("\"payload\""));
    assert!(serialized.contains("\"members\""));
    assert!(serialized.contains("\"algorithm\""));
    assert!(serialized.contains("\"sha256\""));
    // `description` is present in the fixture, so it must round-trip; the
    // omit-on-none contract means a `None` optional is dropped, never serialized as
    // an explicit `null`. Assert that generically over the whole document rather
    // than pinning one hand-picked field.
    assert!(
        !serialized.contains(":null"),
        "omit-on-none violated: a None optional serialized as null:\n{serialized}"
    );

    // Golden wire-shape equality: the struct must serialize back to the fixture's exact JSON
    // shape. The struct round trip above (`original == reparsed`) is symmetric, because a
    // renamed serde key changes both the read and the write and still passes. That leaves the
    // optional `internal.*` and `files[].*` keys, read only by a consumer of the non-public
    // sections, unguarded. Comparing the emitted value against the hand-authored fixture
    // catches a rename or attribute change to any field.
    let raw_value: serde_json::Value = serde_json::from_str(raw).expect("fixture is JSON");
    let struct_value = serde_json::to_value(&original).expect("manifest serializes to Value");
    assert_eq!(
        struct_value, raw_value,
        "manifest wire shape drifted from the fixture: a serde `rename`/attribute change \
         (or a stale fixture). The fixture is the pinned wire contract the node and its consumers \
         share. Reconcile the struct, or regenerate the fixture from it with \
         `GDI_BLESS_MANIFEST_FIXTURE=1 cargo test -p gdi-node-standalone-core manifest_json_round_trips`."
    );
}

/// The published schema's `algorithm` enum must be exactly the algorithms this build
/// accepts.
///
/// `Payload::SHA256` is the single source of that value in Rust, but a `schemars` attribute
/// takes no const expression, so the schema's `enum` carries a second copy of the literal.
/// This test binds the two: add a second algorithm to the build and the schema stops
/// advertising the truth until it is added here too.
///
/// The schema is the earliest place a producer can learn the rule. An algorithm that is
/// schema-valid but unaccepted is hard-rejected by ingest, and on the `diff` path it
/// downgrades the comparison to the weaker source basis instead of failing.
#[cfg(feature = "schema")]
#[test]
fn the_published_schema_encodes_the_only_algorithm_this_build_accepts() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/manifest.schema.json"
    ))
    .expect("the published schema is checked in");
    let schema: serde_json::Value = serde_json::from_str(&raw).expect("schema is JSON");
    let algorithm = &schema["$defs"]["Payload"]["properties"]["algorithm"];
    assert_eq!(
        algorithm["enum"],
        serde_json::json!([gdi_node_standalone_core::model::Payload::SHA256]),
        "docs/manifest.schema.json advertises a different algorithm set than this build \
         accepts. Regenerate with `GDI_BLESS_SCHEMA=1 cargo test -p \
         gdi-node-standalone-core --features schema schema_files` after updating the \
         `schemars(extend(..))` attribute on `Payload::algorithm`."
    );

    // ...and the digest pattern must reject what the description forbids.
    let pattern = schema["$defs"]["PayloadEntry"]["properties"]["sha256"]["pattern"]
        .as_str()
        .expect("sha256 must carry a pattern, not just a prose description");
    assert_eq!(pattern, "^[0-9a-f]{64}$");
}

/// No published schema `description` may name a Rust item.
///
/// `schemars` copies a field's `///` doc verbatim into the schema, so these files are the one
/// place where an internal note becomes an external contract. A doc written for this
/// workspace's readers, naming a Rust type, an intra-doc link or a `#[serde]` attribute, ships
/// to every integrator as the normative description of a wire field, referring to symbols they
/// cannot see.
///
/// The rule is mechanical, so it needs no judgement: a Rust path separator in a description is
/// a leak. Rationale goes in a `//` comment, which `schemars` cannot see. The `///` doc says
/// what the field is.
#[cfg(feature = "schema")]
#[test]
fn no_published_schema_description_names_a_rust_item() {
    /// Every `description` at or below `value`, path-qualified so a failure names where it
    /// lives.
    fn descriptions(value: &serde_json::Value, path: &str, out: &mut Vec<(String, String)>) {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    if k == "description"
                        && let Some(text) = v.as_str()
                    {
                        out.push((path.to_owned(), text.to_owned()));
                    }
                    descriptions(v, &format!("{path}/{k}"), out);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, v) in items.iter().enumerate() {
                    descriptions(v, &format!("{path}/{i}"), out);
                }
            }
            _ => {}
        }
    }

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs");
    let mut checked = 0usize;
    // Enumerated from the published set rather than restated. A hand-written list is a second
    // copy of `SCHEMAS` that drifts silently the moment a schema is added: the new file goes
    // unexamined while this still reports success.
    for (name, _) in gdi_node_standalone_core::schema::SCHEMAS {
        let raw = std::fs::read_to_string(format!("{dir}/{name}"))
            .unwrap_or_else(|e| panic!("{name} is checked in: {e}"));
        let schema: serde_json::Value =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{name} is JSON: {e}"));

        let mut found = Vec::new();
        descriptions(&schema, "", &mut found);
        assert!(
            !found.is_empty(),
            "{name} carries no descriptions at all — this guard would pass vacuously"
        );
        for (path, text) in found {
            checked += 1;
            assert!(
                !text.contains("::"),
                "{name}{path} publishes a Rust path to schema consumers: {text:?}\n\
                 Move the rationale to a `//` comment (schemars only reads `///`), and leave \
                 the doc saying what the field is."
            );
        }
    }
    assert!(checked > 0, "no descriptions were examined");
}
