//! Tier: guard — the README-quickstart bundled sample must match the canonical
//! test fixtures in `test-util`, so the two copies cannot silently diverge.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::Path;
#[test]
fn bundled_sample_matches_canonical_fixture() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let vcf = std::fs::read(fx.join("COVID.monogneic.aggregate.AFs.GRCh38.vcf")).unwrap();
    assert_eq!(
        vcf,
        test_util::covid_vcf_bytes(),
        "bundled sample VCF drifted from test-util canonical"
    );
    let yaml = std::fs::read_to_string(fx.join("covid-package.yaml")).unwrap();
    assert_eq!(
        yaml,
        test_util::covid_package_yaml(),
        "bundled covid-package.yaml drifted from test-util canonical"
    );
}
