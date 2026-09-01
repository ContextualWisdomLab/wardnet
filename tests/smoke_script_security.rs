//! Security regression for the distributable smoke-test credential contract.
//!
//! The smoke harness is executed by operators and CI from a public repository.
//! It must mint an ephemeral per-process credential rather than carrying a
//! reusable administrative secret in source control.

#[test]
fn smoke_script_mints_ephemeral_admin_credential() {
    let script = include_str!("../scripts/smoke.sh");

    assert!(
        !script.contains("dev-secret"),
        "smoke.sh must not ship the historical reusable administrator credential"
    );
    assert!(
        script.contains("secrets.token_hex"),
        "smoke.sh must generate a fresh high-entropy administrator credential"
    );
}
