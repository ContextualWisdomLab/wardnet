//! Architecture RED for the contextual-orchestrator consumer boundary.
//!
//! Wardnet may enforce ingress/admission security around LLM requests, but it
//! must not become the provider/model router. This contract intentionally
//! remains RED while the legacy LiteLLM proxy and caller-selected SOC model
//! are present. The owning contextual-orchestrator release is the prerequisite
//! for the production repair; mutable sibling source is not an acceptable fix.

use std::path::Path;

#[test]
fn wardnet_does_not_ship_a_provider_specific_llm_proxy() {
    assert!(
        !Path::new("src/bin/litellm-virtual-key-proxy.rs").exists(),
        "Wardnet must consume the released contextual-orchestrator contract instead of shipping a LiteLLM-specific proxy"
    );
}

#[test]
fn soc_request_does_not_select_a_concrete_model() {
    let source = include_str!("../src/lib.rs");
    let function_start = source
        .find("fn soc_llm_chat_body")
        .expect("the SOC request builder must remain discoverable until its consumer migration is complete");
    let function_tail = &source[function_start..];
    let function_end = function_tail
        .find("\n/// Extracts the assistant message text")
        .expect("the SOC request builder must retain a bounded source region");
    let function_source = &function_tail[..function_end];

    assert!(
        !function_source.contains("\"model\":"),
        "Wardnet must not choose a model; contextual-orchestrator owns provider/model discovery and routing"
    );
}
