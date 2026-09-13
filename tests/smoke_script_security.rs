//! Security regression for the distributable smoke-test credential contract.
//!
//! The smoke harness is executed by operators and CI from a public repository.
//! It must mint an ephemeral per-process credential rather than carrying a
//! reusable administrative secret in source control.

#[test]
fn smoke_script_mints_ephemeral_admin_credential() {
    let script = include_str!("../scripts/smoke.sh");
    let token_generator = concat!(
        "ADMIN_TOKEN_VALUE=\"$(python3 - <<'PY'\n",
        "import secrets\n",
        "print(secrets.token_hex(16))\n",
        "PY\n",
        ")\""
    );
    let token_forwarding = "ADMIN_TOKEN=\"$ADMIN_TOKEN_VALUE\" \\";

    assert!(
        !script.contains("dev-secret"),
        "smoke.sh must not ship the historical reusable administrator credential"
    );

    let generator_position = script
        .find(token_generator)
        .expect("smoke.sh must assign ADMIN_TOKEN_VALUE from secrets.token_hex(16)");
    let forwarding_position = script
        .find(token_forwarding)
        .expect("smoke.sh must pass ADMIN_TOKEN_VALUE through as ADMIN_TOKEN");

    assert!(
        generator_position < forwarding_position,
        "smoke.sh must mint the ephemeral administrator credential before forwarding it"
    );
    assert_eq!(
        script.matches("ADMIN_TOKEN=").count(),
        1,
        "smoke.sh must expose exactly one ADMIN_TOKEN assignment so a fixed fallback cannot bypass the generated credential"
    );
}
