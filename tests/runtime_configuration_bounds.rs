use waf_ids_ai_soc::parse_u64_env;

#[test]
fn zero_runtime_resource_bounds_fail_closed() {
    assert!(
        parse_u64_env("RATE_LIMIT_WINDOW", Some("0"), 60).is_err(),
        "a zero limiter window must be rejected at bootstrap rather than silently clamped later"
    );
    assert!(
        parse_u64_env("MAX_BODY_BYTES", Some("0"), 1_048_576).is_err(),
        "a zero request-body budget must be rejected as invalid runtime authority"
    );
}

#[test]
fn positive_runtime_resource_bounds_and_defaults_remain_valid() {
    assert_eq!(parse_u64_env("RATE_LIMIT_WINDOW", Some("1"), 60).unwrap(), 1);
    assert_eq!(parse_u64_env("MAX_BODY_BYTES", None, 1_048_576).unwrap(), 1_048_576);
}
