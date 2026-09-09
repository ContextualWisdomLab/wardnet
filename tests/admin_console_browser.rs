//! Real-browser acceptance for Wardnet's shipped embedded admin console.
//!
//! GitHub's `ubuntu-24.04` image publishes `CHROMEWEBDRIVER` and ships matching
//! Chrome/Chromium binaries. Ordinary developer machines without that declared
//! browser capability skip this suite rather than downloading mutable tooling.
//! The browser talks to the real ephemeral Wardnet binary and ChromeDriver's
//! W3C WebDriver/CDP endpoints; no DOM emulator or source-string proxy is used.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use reqwest::Client;
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(unix)]
async fn shipped_console_meets_browser_accessibility_and_responsive_contract() {
    let Some(chromedriver) = chromedriver_path() else {
        eprintln!("browser acceptance skipped: CHROMEWEBDRIVER is not available");
        return;
    };

    let (mut gateway, gateway_url) = spawn_ready_gateway();
    let driver_port = reserve_loopback_port();
    let mut driver = Command::new(chromedriver)
        .arg(format!("--port={driver_port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ChromeDriver from the runner image");

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("build WebDriver client");
    let driver_url = format!("http://127.0.0.1:{driver_port}");
    wait_for_driver(&client, &driver_url).await;

    let session = client
        .post(format!("{driver_url}/session"))
        .json(&json!({
            "capabilities": {
                "alwaysMatch": {
                    "browserName": "chrome",
                    "goog:chromeOptions": {
                        "args": [
                            "--headless=new",
                            "--no-sandbox",
                            "--disable-dev-shm-usage",
                            "--window-size=1440,1200"
                        ]
                    }
                }
            }
        }))
        .send()
        .await
        .expect("create Chrome session")
        .error_for_status()
        .expect("ChromeDriver session status")
        .json::<Value>()
        .await
        .expect("decode ChromeDriver session");
    let session_id = session
        .pointer("/value/sessionId")
        .and_then(Value::as_str)
        .expect("W3C session id")
        .to_owned();

    // Delay browser network traffic just enough to observe the page's shipped
    // loading state after the document itself has loaded. This is not a fake DOM
    // fixture: Chrome still requests the real Wardnet route and API endpoints.
    cdp(
        &client,
        &driver_url,
        &session_id,
        "Network.enable",
        json!({}),
    )
    .await;
    cdp(
        &client,
        &driver_url,
        &session_id,
        "Network.emulateNetworkConditions",
        json!({
            "offline": false,
            "latency": 400,
            "downloadThroughput": -1,
            "uploadThroughput": -1
        }),
    )
    .await;

    wd_post(
        &client,
        &driver_url,
        &session_id,
        "url",
        json!({"url": gateway_url}),
    )
    .await;
    wait_for_document(&client, &driver_url, &session_id).await;
    assert!(
        execute_bool(
            &client,
            &driver_url,
            &session_id,
            "return [...document.querySelectorAll('.muted')].some(e=>e.textContent.trim()==='Loading…');",
        )
        .await,
        "real browser must observe the shipped loading state while API requests are pending"
    );

    cdp(
        &client,
        &driver_url,
        &session_id,
        "Network.emulateNetworkConditions",
        json!({
            "offline": false,
            "latency": 0,
            "downloadThroughput": -1,
            "uploadThroughput": -1
        }),
    )
    .await;

    wait_until_bool(
        &client,
        &driver_url,
        &session_id,
        "return ![...document.querySelectorAll('#routesBody,#threatsBody,#dnsblBody,#readinessBody,#eventsBody')].some(e=>e.textContent.trim()==='Loading…');",
        "normal console API state",
    )
    .await;

    // Keyboard contract: the first Tab must expose the shipped skip link and
    // activating it must transfer focus to the explicit main landmark target.
    send_key(&client, &driver_url, &session_id, "\u{e004}").await;
    assert!(
        execute_bool(
            &client,
            &driver_url,
            &session_id,
            "return document.activeElement === document.querySelector('a.skip') && getComputedStyle(document.activeElement).left === '0px';",
        )
        .await,
        "first keyboard stop must be the visibly focused skip link"
    );
    send_key(&client, &driver_url, &session_id, "\u{e007}").await;
    assert!(
        execute_bool(
            &client,
            &driver_url,
            &session_id,
            "return document.activeElement && document.activeElement.id === 'main';",
        )
        .await,
        "activating the skip link must focus #main"
    );

    // Chrome's accessibility tree is the acceptance authority for computed
    // name/description, not merely the presence of ARIA strings in source.
    let ax_tree = cdp(
        &client,
        &driver_url,
        &session_id,
        "Accessibility.getFullAXTree",
        json!({}),
    )
    .await;
    let nodes = ax_tree
        .pointer("/value/nodes")
        .and_then(Value::as_array)
        .expect("Chrome accessibility tree nodes");
    let admin_token = nodes
        .iter()
        .find(|node| node.pointer("/name/value").and_then(Value::as_str) == Some("Admin token"));
    let admin_token = admin_token.expect("admin token must have a computed accessible name");
    assert_eq!(
        admin_token
            .pointer("/description/value")
            .and_then(Value::as_str),
        Some("Required for management writes and audit log reads."),
        "admin token must expose its computed accessible description"
    );

    assert!(
        execute_bool(
            &client,
            &driver_url,
            &session_id,
            "const k=document.getElementById('kpis'); return k && k.getAttribute('role')==='status' && k.getAttribute('aria-live')==='polite' && k.getAttribute('aria-atomic')==='true';",
        )
        .await,
        "KPI updates must remain one atomic polite status region"
    );

    // Empty admin credentials intentionally exercise the permission-denied
    // presentation path on the real audit endpoint while the gateway itself is
    // configured with an admin credential below.
    wait_until_bool(
        &client,
        &driver_url,
        &session_id,
        "const e=document.querySelector('#auditBody .err'); return !!e && e.getClientRects().length>0;",
        "visible audit permission denial",
    )
    .await;

    for width in [375_u64, 768, 1440] {
        wd_post(
            &client,
            &driver_url,
            &session_id,
            "window/rect",
            json!({"width": width, "height": 1000, "x": 0, "y": 0}),
        )
        .await;
        let script = format!(
            "return window.innerWidth === {width} && document.documentElement.scrollWidth <= document.documentElement.clientWidth && [...document.querySelectorAll('header.app,.section-nav,main')].every(e=>{{const r=e.getBoundingClientRect();return r.left>=-0.5 && r.right<=window.innerWidth+0.5;}});"
        );
        assert!(
            execute_bool(&client, &driver_url, &session_id, &script).await,
            "console must not clip or horizontally overflow at {width}px"
        );
    }

    // ChromeDriver's W3C transport is HTTP. The driver keeps its documented
    // local-only default because this test does not pass --allowed-ips, and
    // driver_url is fixed to 127.0.0.1. This disposable session capability is
    // test-process state, not a Wardnet credential, and never leaves the host.
    let _ = client
        // codeql[rust/cleartext-transmission]
        .delete(format!("{driver_url}/session/{session_id}"))
        .send()
        .await;
    terminate(&mut driver, "ChromeDriver");
    terminate(&mut gateway, "Wardnet gateway");
}

fn chromedriver_path() -> Option<PathBuf> {
    let configured = std::env::var_os("CHROMEWEBDRIVER")?;
    let configured = PathBuf::from(configured);
    Some(if configured.is_file() {
        configured
    } else {
        configured.join("chromedriver")
    })
}

fn reserve_loopback_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve loopback port")
        .local_addr()
        .expect("reserved loopback address")
        .port()
}

fn spawn_ready_gateway() -> (Child, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "127.0.0.1:0")
        .env("ADMIN_TOKEN", "browser-test-admin")
        .env_remove("ADMIN_TOKENS")
        .env_remove("WAF_IDS_CREDENTIALS_PATH")
        .env_remove("WAF_IDS_STATE_PATH")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn Wardnet gateway");
    let stdout = child.stdout.take().expect("captured Wardnet stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("read Wardnet readiness line");
    assert!(
        line.contains("listening on"),
        "unexpected startup: {line:?}"
    );
    let address = line
        .split_whitespace()
        .last()
        .expect("listening address")
        .trim()
        .trim_end_matches('/');
    (child, format!("{address}/"))
}

async fn wait_for_driver(client: &Client, driver_url: &str) {
    for _ in 0..50 {
        if client
            .get(format!("{driver_url}/status"))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("ChromeDriver did not become ready");
}

async fn wait_for_document(client: &Client, driver_url: &str, session_id: &str) {
    wait_until_bool(
        client,
        driver_url,
        session_id,
        "return document.readyState === 'complete' && !!document.getElementById('main');",
        "Wardnet console document",
    )
    .await;
}

async fn wait_until_bool(
    client: &Client,
    driver_url: &str,
    session_id: &str,
    script: &str,
    description: &str,
) {
    for _ in 0..50 {
        if execute_bool(client, driver_url, session_id, script).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {description}");
}

async fn send_key(client: &Client, driver_url: &str, session_id: &str, key: &str) {
    wd_post(
        client,
        driver_url,
        session_id,
        "actions",
        json!({
            "actions": [{
                "type": "key",
                "id": "keyboard",
                "actions": [
                    {"type": "keyDown", "value": key},
                    {"type": "keyUp", "value": key}
                ]
            }]
        }),
    )
    .await;
}

async fn execute_bool(client: &Client, driver_url: &str, session_id: &str, script: &str) -> bool {
    wd_post(
        client,
        driver_url,
        session_id,
        "execute/sync",
        json!({"script": script, "args": []}),
    )
    .await
    .pointer("/value")
    .and_then(Value::as_bool)
    .unwrap_or(false)
}

async fn cdp(
    client: &Client,
    driver_url: &str,
    session_id: &str,
    command: &str,
    params: Value,
) -> Value {
    wd_post(
        client,
        driver_url,
        session_id,
        "goog/cdp/execute",
        json!({"cmd": command, "params": params}),
    )
    .await
}

async fn wd_post(
    client: &Client,
    driver_url: &str,
    session_id: &str,
    suffix: &str,
    body: Value,
) -> Value {
    // WebDriver session commands use the same local-only ChromeDriver HTTP
    // transport described at session teardown. The session identifier is an
    // ephemeral test capability, not application sensitive data.
    client
        // codeql[rust/cleartext-transmission]
        .post(format!("{driver_url}/session/{session_id}/{suffix}"))
        .json(&body)
        .send()
        .await
        .expect("WebDriver request")
        .error_for_status()
        .expect("WebDriver status")
        .json::<Value>()
        .await
        .expect("decode WebDriver response")
}

fn terminate(child: &mut Child, name: &str) {
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap_or_else(|error| panic!("send SIGTERM to {name}: {error}"));
    assert!(status.success(), "failed to stop {name}");
    let _ = child.wait();
}
