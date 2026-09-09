#[test]
fn production_postgres_repository_does_not_expose_generic_raw_sql_transaction_surface() {
    let source = std::fs::read_to_string("src/postgres_state.rs")
        .expect("PostgreSQL repository source must exist");

    for forbidden in [
        "pub struct TenantTransaction",
        "pub type TenantTransactionFuture",
        "pub async fn query_scalar_i64",
        "pub async fn query_scalar_text",
        "pub async fn with_tenant_transaction",
    ] {
        assert!(
            !source.contains(forbidden),
            "production PostgreSQL repository API must not expose generic raw-SQL transaction primitive `{forbidden}`; tenant-scoped state access must remain behind typed repository methods"
        );
    }
}
