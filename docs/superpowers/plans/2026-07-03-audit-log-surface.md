# Audit Log Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add buyer-verifiable management audit logs for admin write operations without storing secrets.

**Architecture:** Store audit records in `AppData` so file persistence and support-bundle export use the existing atomic state boundary. Keep audit record creation deterministic in `waf-ids-core`; keep HTTP header parsing and endpoint routing in `src/lib.rs`.

**Tech Stack:** Rust 2024, Axum 0.8, Serde, Tokio, existing JSON state persistence.

## Global Constraints

- Do not use Figma Code Connect.
- Do not add a crate, submodule, database, or logging dependency for this slice.
- Audit logs must not persist `X-Admin-Token` or request bodies.
- Audit logs must cover successful admin writes to routes, threats, DNSBL entries, commercial license metadata, and threat feed imports.
- Failed authorization or validation must not create audit records.
- Audit records must survive restart when `WAF_IDS_STATE_PATH` is configured.

---

### Task 1: Core Audit Model

**Files:**
- Modify: `crates/waf-ids-core/src/lib.rs`
- Test: `crates/waf-ids-core/src/lib.rs`

**Interfaces:**
- Produces: `AuditLogEntry { id, timestamp_unix, actor, action, resource, resource_id, outcome }`
- Produces: `record_audit_log(data: &mut AppData, entry: NewAuditLogEntry) -> AuditLogEntry`
- Produces: `NewAuditLogEntry { timestamp_unix, actor, action, resource, resource_id, outcome }`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn records_audit_logs_with_monotonic_ids() {
    let mut data = AppData::seeded();

    let first = record_audit_log(
        &mut data,
        NewAuditLogEntry {
            timestamp_unix: 10,
            actor: "operator@example.com".to_string(),
            action: "upsert_route".to_string(),
            resource: "route".to_string(),
            resource_id: "edge".to_string(),
            outcome: "success".to_string(),
        },
    );
    let second = record_audit_log(
        &mut data,
        NewAuditLogEntry {
            timestamp_unix: 11,
            actor: "operator@example.com".to_string(),
            action: "update_license".to_string(),
            resource: "commercial_license".to_string(),
            resource_id: "cwlab-enterprise".to_string(),
            outcome: "success".to_string(),
        },
    );

    assert_eq!(first.id, 1);
    assert_eq!(second.id, 2);
    assert_eq!(data.audit_logs.len(), 2);
    assert_eq!(data.next_audit_log_id, 3);
    assert_eq!(data.audit_logs[0].resource_id, "edge");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --locked records_audit_logs_with_monotonic_ids`
Expected: FAIL because `AuditLogEntry`, `NewAuditLogEntry`, `audit_logs`, `next_audit_log_id`, and `record_audit_log` do not exist.

- [ ] **Step 3: Write minimal implementation**

Add the structs, defaulted `audit_logs` and `next_audit_log_id` fields to `AppData`, seed them as empty and `1`, and implement `record_audit_log` by assigning the current `next_audit_log_id`, incrementing it with `saturating_add(1)`, pushing a cloned entry, and returning it.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --locked records_audit_logs_with_monotonic_ids`
Expected: PASS.

### Task 2: HTTP Audit Endpoint And Admin Write Recording

**Files:**
- Modify: `src/lib.rs`
- Test: `src/lib.rs`

**Interfaces:**
- Consumes: `record_audit_log(data, NewAuditLogEntry)`
- Produces: `GET /api/audit-logs -> Vec<AuditLogEntry>`
- Produces: `audit_actor(headers: &HeaderMap) -> String`, reading `x-admin-actor` and falling back to `admin-token`

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn audit_logs_record_successful_admin_writes_without_tokens() {
    let path = temp_state_path("audit");
    let state = AppState::load(AppConfig {
        admin_token: Some("secret".to_string()),
        state_path: Some(path.clone()),
        dnsbl_origin: "dnsbl.example".to_string(),
        event_limit: 10,
    })
    .await
    .unwrap();
    let app = build_app(state);
    let route = RouteConfig {
        id: "audit-route".to_string(),
        path_prefix: "/audit".to_string(),
        upstream: "mock://audit".to_string(),
        mode: EnforcementMode::Monitor,
        enabled: true,
    };

    let unauthorized = app_request(
        &app,
        json_request(Method::POST, "/api/routes", None, &route),
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/routes")
                .header("content-type", "application/json")
                .header("x-admin-token", "secret")
                .header("x-admin-actor", "operator@example.com")
                .body(Body::from(serde_json::to_vec(&route).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let logs: Vec<AuditLogEntry> =
        json_body(app_request(&app, empty_request(Method::GET, "/api/audit-logs")).await).await;
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].actor, "operator@example.com");
    assert_eq!(logs[0].action, "upsert_route");
    assert_eq!(logs[0].resource, "route");
    assert_eq!(logs[0].resource_id, "audit-route");
    assert_eq!(logs[0].outcome, "success");
    assert!(!serde_json::to_string(&logs).unwrap().contains("secret"));

    let persisted: AppData =
        serde_json::from_str(&fs::read_to_string(&path).await.unwrap()).unwrap();
    assert_eq!(persisted.audit_logs.len(), 1);
    let _ = fs::remove_file(path).await;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --locked audit_logs_record_successful_admin_writes_without_tokens`
Expected: FAIL because the audit endpoint and exported `AuditLogEntry` do not exist.

- [ ] **Step 3: Write minimal implementation**

Import and re-export `AuditLogEntry`, `NewAuditLogEntry`, and `record_audit_log`; add `.route("/api/audit-logs", get(list_audit_logs))`; implement `list_audit_logs`; and append `record_audit_log` calls inside existing successful mutation closures for routes, threats, DNSBL entries, commercial license, and threat feed import.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --locked audit_logs_record_successful_admin_writes_without_tokens`
Expected: PASS.

### Task 3: Buyer Evidence And Smoke Coverage

**Files:**
- Modify: `crates/waf-ids-core/src/lib.rs`
- Modify: `src/lib.rs`
- Modify: `scripts/smoke.sh`
- Modify: `docs/commercial/20b-krw-sale-readiness.md`
- Modify: `docs/product-design/enterprise-operator-workflows.md`
- Modify: `docs/analytics/soc-kpis.md`

**Interfaces:**
- Consumes: `data.audit_logs.len()`
- Produces: manifest required endpoint `GET /api/audit-logs`
- Produces: support bundle field `audit_log_count: usize`
- Produces: smoke assertion that audit logs exist after admin writes

- [ ] **Step 1: Write failing assertions**

Add assertions to the commercial readiness test that the evidence manifest includes `/api/audit-logs` and the support bundle reports an `audit_log_count` greater than zero.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --locked commercial_license_feed_readiness_and_bundle_surfaces_work`
Expected: FAIL because audit logs are not yet in the manifest or bundle.

- [ ] **Step 3: Implement minimal buyer evidence updates**

Add audit log count to `SupportBundle`, add `/api/audit-logs` to `buyer_evidence_endpoints`, and document audit logs in the commercial, operator workflow, and KPI docs.

- [ ] **Step 4: Run focused tests and smoke**

Run: `cargo test --locked commercial_license_feed_readiness_and_bundle_surfaces_work`
Expected: PASS.

Run: `scripts/smoke.sh`
Expected: `smoke ok: ...`

### Task 4: Full Verification

**Files:**
- No new files beyond this plan.

**Interfaces:**
- Produces: verified branch ready for PR.

- [ ] **Step 1: Format and lint**

Run: `cargo fmt --check`
Expected: exit 0.

Run: `actionlint`
Expected: exit 0.

Run: `git diff --check`
Expected: exit 0.

- [ ] **Step 2: Rust verification**

Run: `cargo test --locked --workspace`
Expected: all tests pass.

Run: `cargo clippy --locked --workspace --all-targets -- -D warnings`
Expected: exit 0.

- [ ] **Step 3: Security and coverage**

Run: `cargo audit`
Expected: no vulnerabilities.

Run: `cargo deny check advisories`
Expected: `advisories ok`.

Run: `LLVM_COV=/opt/homebrew/opt/llvm/bin/llvm-cov LLVM_PROFDATA=/opt/homebrew/opt/llvm/bin/llvm-profdata cargo llvm-cov --workspace --all-features --fail-under-lines 100 --show-missing-lines`
Expected: line coverage remains 100.00%.
