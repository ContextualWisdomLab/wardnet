use std::fs;
use std::path::Path;

fn repo_file(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

#[test]
fn product_quality_ambition_is_not_a_customer_contract_threshold() {
    let core = repo_file("crates/waf-ids-core/src/lib.rs");
    let customer_contract = repo_file("docs/commercial/2b-krw-customer-contract-readiness.md");
    let product_quality = repo_file("docs/commercial/usd-20b-product-quality-bar.md");
    let legacy = repo_file("docs/commercial/20b-krw-sale-readiness.md");

    assert!(
        core.contains("pub const TARGET_SALE_VALUE_KRW: u64 = 2_000_000_000;"),
        "the existing customer-contract readiness threshold must remain 2B KRW unless a separate product decision changes it"
    );
    assert!(
        !core.contains("TARGET_SALE_VALUE_KRW: u64 = 20_000_000_000"),
        "the product-quality ambition must not be encoded as tenant contract value"
    );

    assert!(customer_contract.contains("2B KRW Customer Contract Readiness"));
    assert!(customer_contract.contains("annual_contract_value_krw"));
    assert!(customer_contract.contains("not product valuation"));
    assert!(customer_contract.contains("usd-20b-product-quality-bar.md"));

    assert!(product_quality.contains("USD 20 billion"));
    assert!(product_quality.contains(
        "not a tenant price, contract-value threshold, billing rule, or accounting fact"
    ));
    assert!(product_quality.contains("Buyer-visible evidence"));
    assert!(product_quality.contains("2b-krw-customer-contract-readiness.md"));

    assert!(legacy.contains("Compatibility notice"));
    assert!(legacy.contains("2b-krw-customer-contract-readiness.md"));
    assert!(legacy.contains("usd-20b-product-quality-bar.md"));
    assert!(legacy.contains("must not be used as numeric authority"));
}

#[test]
fn public_repository_surfaces_are_single_sourced_and_boundary_accurate() {
    const DEEPWIKI_BADGE: &str =
        "[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ContextualWisdomLab/wardnet)";

    let readme = repo_file("README.md");
    let pages = repo_file("docs/index.md");

    assert_eq!(
        readme.matches(DEEPWIKI_BADGE).count(),
        1,
        "README must expose exactly one repository-specific DeepWiki entry point"
    );
    assert!(pages.contains("# Wardnet"));
    assert!(pages.contains("Rust-first gateway and SOC control plane"));
    assert!(pages.contains("does not claim complete WAF, IDS, SIEM, or SOAR coverage"));
    assert!(pages.contains(DEEPWIKI_BADGE));
}
