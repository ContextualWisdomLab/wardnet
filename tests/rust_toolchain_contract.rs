//! Repository contracts for the reviewed Rust compiler baseline.

const RUST_TOOLCHAIN: &str = include_str!("../rust-toolchain.toml");
const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");
const DEPENDABOT: &str = include_str!("../.github/dependabot.yml");

#[test]
fn pinned_toolchain_is_consistent_in_local_and_ci_contracts() {
    assert!(RUST_TOOLCHAIN.contains("channel = \"1.97.1\""));
    assert!(!RUST_TOOLCHAIN.contains("channel = \"stable\""));
    let ci_toolchains = CI_WORKFLOW
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("toolchain: "))
        .collect::<Vec<_>>();
    assert!(!ci_toolchains.is_empty());
    assert!(ci_toolchains.iter().all(|toolchain| *toolchain == "1.97.1"));
}

#[test]
fn stable_toolchain_updates_are_reviewable() {
    assert!(DEPENDABOT.contains("package-ecosystem: rust-toolchain"));
    assert!(DEPENDABOT.contains("interval: weekly"));
}
