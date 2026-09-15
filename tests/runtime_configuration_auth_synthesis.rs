use waf_ids_ai_soc::run_from_env;

fn clear_auth_bootstrap_env() {
    for name in [
        "BIND_ADDR",
        "ADMIN_TOKEN",
        "ADMIN_TOKENS",
        "WAF_IDS_CREDENTIALS_PATH",
        "WAF_IDS_STATE_PATH",
        "DNSBL_ORIGIN",
        "EVENT_LIMIT",
        "RATE_LIMIT",
        "RATE_LIMIT_WINDOW",
        "MAX_BODY_BYTES",
    ] {
        unsafe { std::env::remove_var(name) };
    }
}

#[tokio::test]
async fn runtime_snapshot_preserves_public_bind_write_auth_gate() {
    clear_auth_bootstrap_env();
    unsafe { std::env::set_var("BIND_ADDR", "0.0.0.0:0") };

    let missing_admin = run_from_env(Box::pin(std::future::ready(())))
        .await
        .expect_err("public management bind without a write-capable administrator must fail closed")
        .to_string();
    assert!(
        missing_admin.contains("refusing to bind 0.0.0.0:0"),
        "unexpected public-bind denial: {missing_admin}"
    );

    clear_auth_bootstrap_env();
    unsafe {
        std::env::set_var("BIND_ADDR", "0.0.0.0:0");
        std::env::set_var("ADMIN_TOKENS", "reader:auditor:readonly");
    }
    let readonly_admin = run_from_env(Box::pin(std::future::ready(())))
        .await
        .expect_err("read-only credentials must not authorize a public management bind")
        .to_string();
    assert!(
        readonly_admin.contains("refusing to bind 0.0.0.0:0"),
        "unexpected read-only public-bind denial: {readonly_admin}"
    );

    clear_auth_bootstrap_env();
    unsafe {
        std::env::set_var("BIND_ADDR", "0.0.0.0:0");
        std::env::set_var("ADMIN_TOKENS", "writer:ops:admin");
    }
    run_from_env(Box::pin(std::future::ready(())))
        .await
        .expect("a header-presentable write-capable administrator must allow the public bind");

    clear_auth_bootstrap_env();
}
