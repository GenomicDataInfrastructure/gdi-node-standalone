//! Criterion benchmark for the cold-start [`hydrate_from_disk`] reload — the
//! O(datasets) work the node does at boot to rebuild its in-memory metadata cache
//! from each `data_dir/{id}/manifest.json`.
//!
//! The other benches time a single unit, one codec or one file. This one tracks the boot cost
//! that scales with dataset count. The `N_DATASETS` synthetic dataset directories are written
//! once, outside the timed loop, so numbers are comparable across runs. A sanity assert
//! confirms the fixtures hydrate, so the numbers reflect real reload work rather than an
//! empty-directory walk.
#![allow(
    clippy::disallowed_methods,
    reason = "test/bench code writes plain files: durability and atomicity are not properties under test"
)]

use std::hint::black_box;
use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use gdi_node_standalone_core::cache::{MetadataCache, StatusIndex, StatusWrite, hydrate_from_disk};
use gdi_node_standalone_core::model::{
    Agent, Assembly, DatasetMode, Internal, LocalizedText, Manifest, ManifestConfig,
    ManifestMetadata,
};
use gdi_node_standalone_core::suppression::SuppressionSet;

const N_DATASETS: usize = 500;

/// A valid 17-digit (`YYYYMMDDHHMMSSmmm`) GOE dataset id, varied by `i`.
fn dataset_id(i: usize) -> String {
    format!("GDI-EE-UTARTU-20260409{:09}", 100_000_000 + i)
}

/// Write one minimal published dataset dir (`{id}/manifest.json`) — the shape
/// `hydrate_from_disk` parses.
fn write_dataset(data_dir: &Path, id: &str) {
    let dir = data_dir.join(id);
    std::fs::create_dir_all(&dir).expect("create dataset dir");
    let manifest = Manifest {
        payload: None,
        metadata: ManifestMetadata {
            dataset_id: id.to_owned(),
            catalog: "gdi-aggregated".to_owned(),
            title: LocalizedText::Plain("bench dataset".to_owned()),
            description: None,
            access_rights: "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
                .to_owned(),
            applicable_legislation: vec!["http://data.europa.eu/eli/reg/2025/327/oj".to_owned()],
            license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
            creator: vec![Agent {
                name: "Bench".to_owned(),
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
            number_of_records: None,
            populations: None,
        },
        files: Vec::new(),
        internal: Internal::default(),
        config: ManifestConfig {
            mode: DatasetMode::Aggregated,
            block_range: 10_000_000,
            af_source: None,
            af_source_reference: None,
            min_allele_count: 0,
            hide_lower_counts: None,
            assembly: Assembly {
                reference: "GRCh38".to_owned(),
            },
            manifest_version: 1,
            generated_by: "bench".to_owned(),
        },
    };
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");
}

fn bench_hydrate(c: &mut Criterion) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path();
    for i in 0..N_DATASETS {
        write_dataset(data_dir, &dataset_id(i));
    }
    // Sanity, outside the timed loop: the fixtures must hydrate fully, or this times an
    // empty directory walk instead of real reload work.
    {
        let cache = MetadataCache::new();
        let loaded = hydrate_from_disk(
            data_dir,
            StatusWrite::unshared(),
            &StatusIndex::new(),
            &cache,
            &SuppressionSet::default(),
            &|_| false,
        )
        .loaded;
        assert_eq!(loaded, N_DATASETS, "fixture must hydrate fully");
    }

    c.bench_function("hydrate_from_disk_500_datasets", |b| {
        b.iter(|| {
            let cache = MetadataCache::new();
            let status = StatusIndex::new();
            let suppressions = SuppressionSet::default();
            let loaded = hydrate_from_disk(
                black_box(data_dir),
                StatusWrite::unshared(),
                black_box(&status),
                black_box(&cache),
                black_box(&suppressions),
                &|_| false,
            );
            black_box(loaded);
        });
    });
}

criterion_group!(benches, bench_hydrate);
criterion_main!(benches);
