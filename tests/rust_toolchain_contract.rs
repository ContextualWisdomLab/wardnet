//! Repository contracts for the reviewed Rust compiler baseline.

const RUST_TOOLCHAIN: &str = include_str!("../rust-toolchain.toml");
const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");
const DEPENDABOT: &str = include_str!("../.github/dependabot.yml");

#[test]
fn stable_toolchain_is_exact_in_local_and_ci_contracts() {
    assert!(RUST_TOOLCHAIN.contains("channel = \"1.97.1\""));
    assert!(!RUST_TOOLCHAIN.contains("channel = \"stable\""));
    assert_eq!(CI_WORKFLOW.matches("toolchain: 1.97.1").count(), 1);
    assert!(!CI_WORKFLOW.contains("toolchain: stable"));
}

#[test]
fn stable_toolchain_updates_are_reviewable() {
    assert!(DEPENDABOT.contains("package-ecosystem: rust-toolchain"));
    assert!(DEPENDABOT.contains("interval: weekly"));
}
