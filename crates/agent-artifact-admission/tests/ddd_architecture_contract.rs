//! Architectural fitness checks for the Agent Artifact Admission bounded context.
//!
//! These tests intentionally inspect module imports and module names. They are not
//! behavior tests; they protect the dependency direction that keeps the domain
//! vocabulary usable without Axum, Tokio, filesystem, or deployment concerns.

const DOMAIN_SOURCES: &[(&str, &str)] = &[
    ("admission.rs", include_str!("../src/admission.rs")),
    ("artifact_variant.rs", include_str!("../src/artifact_variant.rs")),
    ("policy.rs", include_str!("../src/policy.rs")),
];

const FORBIDDEN_DOMAIN_DEPENDENCIES: &[&str] = &[
    "axum::",
    "tokio::",
    "std::fs",
    "std::net",
    "std::path",
    "FileAuditSink",
    "AdmissionServiceConfig",
];

#[test]
fn domain_modules_do_not_depend_on_delivery_or_infrastructure() {
    for (path, source) in DOMAIN_SOURCES {
        for forbidden in FORBIDDEN_DOMAIN_DEPENDENCIES {
            assert!(
                !source.contains(forbidden),
                "{path} crosses the Agent Artifact Admission domain boundary via {forbidden}"
            );
        }
    }
}

#[test]
fn bounded_context_does_not_gain_ambiguous_dumping_modules() {
    let crate_root = include_str!("../src/lib.rs");
    for ambiguous in [
        "mod utils;",
        "mod helpers;",
        "mod common;",
        "mod services;",
        "mod shared;",
        "mod misc;",
        "mod legacy;",
        "mod model;",
    ] {
        assert!(
            !crate_root.contains(ambiguous),
            "Agent Artifact Admission must express domain responsibility instead of adding `{ambiguous}`"
        );
    }
}

#[test]
fn domain_policy_remains_independent_of_http_and_audit_adapters() {
    let policy = include_str!("../src/policy.rs");
    for adapter in [
        "crate::http",
        "crate::config",
        "FileAuditSink",
        "MemoryAuditSink",
    ] {
        assert!(
            !policy.contains(adapter),
            "policy.rs must not depend on adapter concern `{adapter}`"
        );
    }
}
