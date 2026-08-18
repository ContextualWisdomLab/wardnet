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

    assert_eq!(
        function_source
            .matches("\"orchestration_mode\": \"auto\"")
            .count(),
        1,
        "the SOC request builder must declare exactly one auto orchestration policy"
    );

    let model_position = function_source
        .find("\"model\"")
        .expect("the SOC request must retain its model selector");
    let policy_position = function_source
        .find("\"orchestration_mode\": \"auto\"")
        .expect("the SOC request must retain the explicit auto policy");
    let messages_position = function_source
        .find("\"messages\"")
        .expect("the SOC request must retain its messages payload");
    assert!(
        model_position < policy_position && policy_position < messages_position,
        "the orchestration policy must remain in the generated SOC chat payload"
    );
}
