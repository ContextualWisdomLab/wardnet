//! Contract test for the contextual-orchestrator SOC request policy.

#[test]
fn soc_llm_request_explicitly_delegates_to_auto_policy() {
    let source = include_str!("../src/lib.rs");
    assert!(source.contains("orchestration_mode"));
    assert!(source.contains("auto"));
}
