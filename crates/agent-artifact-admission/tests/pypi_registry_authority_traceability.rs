#[test]
fn direct_pip_registry_authority_keeps_causal_security_traceability() {
    let source = include_str!("../src/pypi_registry_authority.rs");

    for reference in [
        "https://pip.pypa.io/en/latest/reference/requirements-file-format/",
        "https://peps.python.org/pep-0503/",
        "https://peps.python.org/pep-0493/",
        "https://doi.org/10.6028/NIST.SP.800-218",
    ] {
        assert!(
            source.contains(reference),
            "direct-pip registry/trust authority must retain causal documentation reference: {reference}"
        );
    }
}
