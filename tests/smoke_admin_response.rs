//! Execute the shipped smoke harness's admin-page check against real page bytes.
//! A fixture-owned loopback server controls packet timing without live services.

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

const TITLE: &str = "ContextualWisdomLab WAF/IDS/AI SOC Gateway";

fn actual_admin_check() -> &'static str {
    let script = include_str!("../scripts/smoke.sh");
    let start = script.find("curl -fsS \"$BASE_URL/admin\"").unwrap();
    let end = script[start..].find("\n\nunauthorized_code=").unwrap() + start;
    &script[start..end]
}

struct FixtureDirectory(PathBuf);

impl FixtureDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wardnet smoke admin {} {}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Replay a single response with a title-bearing first chunk and delayed tail.
/// The bytes are the application's actual /admin body, not a replacement page.
fn execute_check(body: Vec<u8>, status: u16, truncate: bool) -> (Output, FixtureDirectory) {
    let directory = FixtureDirectory::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "fixture server accept timed out");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("fixture accept failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut chunk = [0; 1024];
            let size = stream.read(&mut chunk).unwrap();
            assert!(
                size > 0 && request.len() + size <= 4096,
                "invalid fixture request framing"
            );
            request.extend_from_slice(&chunk[..size]);
        }
        assert!(request.starts_with(b"GET /admin HTTP/1.1\r\n"));
        let header = format!(
            "HTTP/1.1 {status} Fixture\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).unwrap();
        let split = 8192.min(body.len());
        stream.write_all(&body[..split]).unwrap();
        stream.flush().unwrap();
        thread::sleep(Duration::from_millis(150));
        // The pre-fix consumer may already have closed its output pipe. A
        // socket error here is evidence of that early consumer, not a panic.
        if !truncate {
            let _ = stream.write_all(&body[split..]);
        }
    });
    let shell = format!("set -euo pipefail\n{}\n", actual_admin_check());
    let mut child = Command::new("bash")
        .args(["-c", &shell])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("BASE_URL", format!("http://{address}"))
        .env("TMP_DIR", &directory.0)
        .env("NO_PROXY", "127.0.0.1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut timed_out = false;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            timed_out = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    server.join().unwrap();
    assert!(!timed_out, "smoke check exceeded owned diagnostic deadline");
    (output, directory)
}

#[tokio::test]
async fn admin_smoke_check_accepts_complete_delayed_production_response() {
    let response = build_app(AppState::seeded(None))
        .oneshot(
            Request::builder()
                .uri("/admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1_000_000)
        .await
        .unwrap()
        .to_vec();
    assert!(
        body.len() > 16_384,
        "production page must exercise multiple curl writes"
    );
    assert!(std::str::from_utf8(&body[..8192]).unwrap().contains(TITLE));
    let (output, directory) = execute_check(body.clone(), 200, false);
    let captured = directory.0.join("admin.html");
    assert_eq!(
        std::fs::read(captured).unwrap(),
        body,
        "smoke must retain the complete response"
    );
    assert!(
        output.status.success(),
        "complete HTTP200 admin response failed shipped smoke check: exit={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn admin_smoke_check_rejects_complete_response_without_title() {
    let (output, directory) = execute_check(vec![b'x'; 32_768], 200, false);
    assert_eq!(
        output.status.code(),
        Some(1),
        "missing title must fail grep"
    );
    assert_eq!(
        std::fs::read(directory.0.join("admin.html")).unwrap(),
        vec![b'x'; 32_768]
    );
}

#[test]
fn admin_smoke_check_rejects_http_error_even_with_a_title() {
    let body = format!("{TITLE}{}", "x".repeat(32_768)).into_bytes();
    let (output, _) = execute_check(body, 503, false);
    assert_eq!(
        output.status.code(),
        Some(22),
        "curl HTTP error must propagate"
    );
}

#[test]
fn admin_smoke_check_rejects_truncation_after_matching_title() {
    let body = format!("{TITLE}{}", "x".repeat(32_768)).into_bytes();
    let (output, directory) = execute_check(body, 200, true);
    assert_eq!(
        output.status.code(),
        Some(18),
        "curl truncated response must propagate"
    );
    assert_eq!(
        std::fs::metadata(directory.0.join("admin.html"))
            .unwrap()
            .len(),
        8192
    );
}
