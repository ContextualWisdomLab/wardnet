//! Contract test for the contextual-orchestrator SOC request policy.

#[test]
fn soc_llm_request_explicitly_delegates_to_auto_policy() {
    let source = include_str!("../src/lib.rs");
    let function_start = source
        .find("fn soc_llm_chat_body")
        .expect("the SOC request builder must remain present");
    let function_tail = &source[function_start..];
    let function_end = function_tail
        .find("\n/// Extracts the assistant message text")
        .expect("the SOC request builder must retain a bounded source region");
    let function_source = &function_tail[..function_end];

    let policy = "\"orchestration_mode\": \"auto\"";
    let policy_positions = source
        .match_indices(policy)
        .map(|(position, _)| position)
        .collect::<Vec<_>>();
    let function_end_absolute = function_start + function_end;

    assert_eq!(
        policy_positions.len(),
        1,
        "the SOC request builder must declare exactly one auto orchestration policy"
    );
    assert!(
        policy_positions[0] >= function_start && policy_positions[0] < function_end_absolute,
        "the auto orchestration policy must be confined to soc_llm_chat_body"
    );

    let policy_position = function_source
        .find("\"orchestration_mode\": \"auto\"")
        .expect("the SOC request must retain the explicit auto policy");
    let messages_position = function_source
        .find("\"messages\"")
        .expect("the SOC request must retain its messages payload");
    assert!(
        !function_source.contains("\"model\""),
        "the SOC request must delegate concrete model selection to contextual-orchestrator"
    );
    assert!(
        policy_position < messages_position,
        "the orchestration policy must remain in the generated SOC chat payload"
    );
}
