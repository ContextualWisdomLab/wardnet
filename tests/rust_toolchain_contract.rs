//! Repository contracts for the reviewed Rust compiler baseline.

const RUST_TOOLCHAIN: &str = include_str!("../rust-toolchain.toml");
const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");
const DEPENDABOT: &str = include_str!("../.github/dependabot.yml");

fn pinned_channel() -> String {
    RUST_TOOLCHAIN
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("channel = \""))
        .and_then(|line| line.strip_suffix('"'))
        .expect("rust-toolchain.toml must declare a channel")
        .to_string()
}

#[test]
fn pinned_toolchain_is_consistent_in_local_and_ci_contracts() {
    let pinned_channel = pinned_channel();
    assert_eq!(pinned_channel, "1.97.1");
    assert!(!RUST_TOOLCHAIN.contains("channel = \"stable\""));
    assert!(CI_WORKFLOW.contains("id: pinned-toolchain"));
    assert!(CI_WORKFLOW.contains("sed -n 's/^channel = "));
    assert!(CI_WORKFLOW.contains("toolchain: ${{ steps.pinned-toolchain.outputs.version }}"));
}

#[test]
fn stable_toolchain_updates_are_reviewable() {
    let mut in_rust_toolchain_block = false;
    let mut saw_weekly = false;

    for line in DEPENDABOT.lines().map(str::trim) {
        if line.starts_with("- package-ecosystem: ") {
            in_rust_toolchain_block = line == "- package-ecosystem: rust-toolchain";
            continue;
        }
        if in_rust_toolchain_block && line == "interval: weekly" {
            saw_weekly = true;
        }
    }

    assert!(
        saw_weekly,
        "rust-toolchain updater must stay on a weekly cadence"
    );
}
