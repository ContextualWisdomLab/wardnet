//! Causal RED proof that reaches the durable PostgreSQL facts before asserting
//! Wardnet's missing commit-outcome classification.
//!
//! The canonical fault fixture lives in the sibling integration test. Including
//! it here keeps the protocol mechanics byte-identical while this proof orders
//! the acceptance assertions so an infrastructure or fixture defect cannot be
//! mistaken for the intended application-boundary RED.

include!("postgres_publication_commit_ambiguity.rs");

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committed_ack_loss_proves_durable_state_before_commit_unknown_red() {
    let Some(container) = prepare_database() else {
        return;
    };
    let proxy = CommitFaultProxy::start(container.host_port);
    let pool = connect_pool(&container, &proxy).await;
    let tenant = TenantId::parse("tenant-a").expect("tenant identity must validate");
    let other_tenant = TenantId::parse("tenant-b").expect("tenant identity must validate");

    assert_eq!(
        pool.publish_reputation_source(&tenant, &publication(None, "generation-8", 8))
            .await
            .expect("baseline publication must commit"),
        PublicationOutcome::Committed
    );

    let generation_9 = publication(Some("generation-8"), "generation-9", 9);
    proxy.arm_drop_after_commit();
    let ambiguous = pool.publish_reputation_source(&tenant, &generation_9).await;
    assert!(
        ambiguous.is_err(),
        "lost COMMIT acknowledgement must never be reported as known success"
    );
    assert!(proxy.commit_was_forwarded(), "COMMIT must reach PostgreSQL");
    assert!(
        proxy.commit_completed_before_drop(),
        "fixture must observe CommandComplete plus ReadyForQuery before dropping the acknowledgement"
    );
    assert_eq!(
        proxy.connection_count(),
        1,
        "pool must not reconnect or replay before an explicit caller retry"
    );
    assert_eq!(
        generation_9_residue(&container).trim(),
        "1:1:1:1",
        "server-completed COMMIT must leave exactly one generation/publication/audit/head tuple"
    );

    assert_eq!(
        pool.publish_reputation_source(&tenant, &generation_9)
            .await
            .expect("explicit identical reconciliation must use durable state"),
        PublicationOutcome::Replay
    );
    assert_eq!(generation_9_residue(&container).trim(), "1:1:1:1");
    assert_conflict(
        pool.publish_reputation_source(
            &tenant,
            &publication_with(
                Some("generation-8"),
                "generation-9",
                9,
                "provenance-generation-9-divergent",
                "subject:commit-fixture",
                "decision:publish-generation-9-9",
            ),
        )
        .await,
        "divergent evidence must not reconcile the committed ambiguous transaction",
    );

    let probe = pool
        .probe_unbound_context()
        .await
        .expect("replacement checkout must remain usable");
    assert_eq!(probe.tenant_id(), None);
    assert!(
        pool.current_reputation_source_publication(&other_tenant, "urlhaus")
            .await
            .expect("cross-tenant lookup must remain a valid empty read")
            .is_none(),
        "tenant B must not see tenant A's committed publication"
    );

    // All protocol, durability, idempotency and isolation facts above must pass
    // before this final causal RED is allowed to fail.
    assert_commit_unknown(ambiguous);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn precommit_loss_proves_rollback_before_commit_unknown_red() {
    let Some(container) = prepare_database() else {
        return;
    };
    let proxy = CommitFaultProxy::start(container.host_port);
    let pool = connect_pool(&container, &proxy).await;
    let tenant = TenantId::parse("tenant-a").expect("tenant identity must validate");
    let other_tenant = TenantId::parse("tenant-b").expect("tenant identity must validate");

    assert_eq!(
        pool.publish_reputation_source(&tenant, &publication(None, "generation-8", 8))
            .await
            .expect("baseline publication must commit"),
        PublicationOutcome::Committed
    );

    let generation_9 = publication(Some("generation-8"), "generation-9", 9);
    proxy.arm_drop_before_commit();
    let ambiguous = pool.publish_reputation_source(&tenant, &generation_9).await;
    assert!(
        ambiguous.is_err(),
        "lost COMMIT transport must never be reported as known success"
    );
    assert!(proxy.commit_was_withheld(), "fixture must intercept COMMIT");
    assert!(
        !proxy.commit_was_forwarded(),
        "COMMIT must not reach PostgreSQL"
    );
    assert!(!proxy.commit_completed_before_drop());
    assert_eq!(
        proxy.connection_count(),
        1,
        "pool must not reconnect or replay before an explicit caller retry"
    );

    await_generation_9_absent(&container);
    let current = assert_success(
        psql(
            &container,
            "SELECT source_generation FROM public.reputation_source_publication_head WHERE tenant_id = 'tenant-a' AND source_id = 'urlhaus';",
        ),
        "inspect head after pre-COMMIT loss",
    );
    assert_eq!(current.trim(), "generation-8");

    assert_eq!(
        pool.publish_reputation_source(&tenant, &generation_9)
            .await
            .expect("explicit retry after proven rollback may commit"),
        PublicationOutcome::Committed
    );
    assert_eq!(generation_9_residue(&container).trim(), "1:1:1:1");

    let probe = pool
        .probe_unbound_context()
        .await
        .expect("replacement checkout must remain usable");
    assert_eq!(probe.tenant_id(), None);
    assert!(
        pool.current_reputation_source_publication(&other_tenant, "urlhaus")
            .await
            .expect("cross-tenant lookup must remain a valid empty read")
            .is_none(),
        "tenant B must not see tenant A's retried publication"
    );

    // Only after rollback, retry and tenant-isolation evidence is proven do we
    // require the stable unknown-outcome classification from the first call.
    assert_commit_unknown(ambiguous);
}
