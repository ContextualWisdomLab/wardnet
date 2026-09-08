use waf_ids_ai_soc::postgres_state::{PostgresStateError, PostgresTenantPool};

#[tokio::test]
async fn loopback_fixture_rejects_non_loopback_hostaddr_override() {
    let result = PostgresTenantPool::connect_loopback_test(
        "host=localhost hostaddr=192.0.2.1 port=1 user=postgres dbname=postgres sslmode=disable connect_timeout=1",
        1,
    )
    .await;

    match result {
        Err(PostgresStateError::InvalidLoopbackFixture(_)) => {}
        Err(other) => {
            panic!("non-loopback hostaddr must be rejected before connector I/O; got {other}")
        }
        Ok(_) => panic!("non-loopback hostaddr must never produce a plaintext fixture pool"),
    }
}
