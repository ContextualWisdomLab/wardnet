//! Persisted DNSBL publication evidence must agree across all buyer-facing APIs.
//! These fixtures do not start a server, change credentials, or mutate live state.

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::Value;
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppConfig, AppState, build_app};
use waf_ids_core::{AppData, LicenseStatus, SecurityEvent, ThreatFeedStatus};

struct StateFixture(PathBuf);

impl Drop for StateFixture {
    fn drop(&mut self) {
        // Only this test's unique disposable state file is owned here.
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn read(app: &axum::Router, path: &str) -> Vec<u8> {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{path}");
    to_bytes(response.into_body(), 1_000_000)
        .await
        .unwrap()
        .to_vec()
}

fn assert_readiness(value: &Value, published: bool) {
    assert_eq!(value["ready_for_enterprise_sale"], published);
    assert_eq!(
        value["readiness_level"],
        if published {
            "sale_ready"
        } else {
            "implementation_required"
        }
    );
    assert_eq!(
        value["blockers"],
        if published {
            serde_json::json!([])
        } else {
            serde_json::json!(["dnsbl_publication"])
        }
    );
}

#[tokio::test]
async fn persisted_unpublishable_rows_do_not_advertise_sale_readiness() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut data = AppData::seeded();
    data.commercial.license_status = LicenseStatus::Active;
    data.commercial.license_id = Some("fixture-license".into());
    data.commercial.licensee = Some("fixture buyer".into());
    data.commercial.annual_contract_value_krw = Some(2_000_000_000);
    data.threat_feeds.push(ThreatFeedStatus {
        feed_id: "fixture-feed".into(),
        source: "fixture".into(),
        last_updated_unix: now,
        threat_count: 1,
        dnsbl_count: 0,
        ttl_seconds: 600,
    });
    data.events.push(SecurityEvent {
        id: 1,
        timestamp_unix: now,
        client_ip: None,
        route_id: Some("demo".into()),
        action: "monitored".into(),
        reason: "fixture".into(),
        score: 0,
        path: "/demo".into(),
    });
    let valid = data.dnsbl[0].clone();
    let mut invalid_rows = Vec::new();
    let mut entry = valid.clone();
    entry.address = "2001:db8::10".parse().unwrap();
    invalid_rows.push(entry);
    let mut entry = valid.clone();
    entry.ttl_seconds = 0;
    invalid_rows.push(entry);
    let mut entry = valid.clone();
    entry.ttl_seconds = 2_147_483_648;
    invalid_rows.push(entry);
    let mut entry = valid.clone();
    entry.code = "8.8.8.8".into();
    invalid_rows.push(entry);
    let mut entry = valid.clone();
    entry.code = "127.0.0.2\nforged IN TXT \"extra\"".into();
    invalid_rows.push(entry);
    let mut entry = valid.clone();
    entry.reason = "x".repeat(65_280);
    invalid_rows.push(entry);

    for (case, invalid) in invalid_rows.into_iter().enumerate() {
        for published in [false, true] {
            data.dnsbl = vec![invalid.clone()];
            if published {
                data.dnsbl.push(valid.clone());
            }
            let fixture = StateFixture(std::env::temp_dir().join(format!(
                "wardnet-publication-readiness-{}-{}-{case}-{published}.json",
                std::process::id(),
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
            )));
            let original = serde_json::to_vec_pretty(&data).unwrap();
            std::fs::write(&fixture.0, &original).unwrap();
            // Repeat a fresh load to exercise restart/read-only preservation.
            for _ in 0..2 {
                let mut config = AppConfig::memory(None);
                config.state_path = Some(fixture.0.clone());
                let app = build_app(AppState::load(config).await.unwrap());
                let zone = String::from_utf8(read(&app, "/dnsbl/zone").await).unwrap();
                assert_eq!(zone.lines().count(), if published { 4 } else { 2 });
                let readiness: Value =
                    serde_json::from_slice(&read(&app, "/api/commercial/readiness").await).unwrap();
                assert_readiness(&readiness, published);
                let manifest: Value =
                    serde_json::from_slice(&read(&app, "/api/commercial/evidence-manifest").await)
                        .unwrap();
                assert_readiness(&manifest, published);
                assert_eq!(
                    manifest["runtime_counts"]["dnsbl_entry_count"],
                    data.dnsbl.len()
                );
                let bundle: Value =
                    serde_json::from_slice(&read(&app, "/api/support-bundle").await).unwrap();
                assert_readiness(&bundle["readiness"], published);
                assert_readiness(&bundle["evidence_manifest"], published);
                assert_eq!(bundle["dnsbl_entry_count"], data.dnsbl.len());
                assert_eq!(
                    std::fs::read(&fixture.0).unwrap(),
                    original,
                    "read mutated persisted evidence"
                );
            }
            let fixture_path = fixture.0.clone();
            drop(fixture);
            assert!(
                !fixture_path.exists(),
                "test-owned persisted fixture leaked"
            );
        }
    }
}
