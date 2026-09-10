//! The `validate_pkg` field validators the wizard needs must stay reachable from the
//! tool crate, i.e. `pub` rather than `pub(crate)` or private.

#[test]
fn wizard_field_validators_are_pub() {
    use gdi_node_standalone_core::validate_pkg as v;
    assert!(v::validate_email("e", "mailto:a@b.co").is_ok());
    assert!(v::validate_iri("license", "https://x.example/l").is_ok());
    assert!(v::validate_enum("accessRights", v::ACCESS_RIGHTS[0], v::ACCESS_RIGHTS).is_ok());
    assert!(gdi_node_standalone_core::chrom::is_known_assembly("GRCh38"));
    assert!(!gdi_node_standalone_core::chrom::is_known_assembly("hg38"));
}
