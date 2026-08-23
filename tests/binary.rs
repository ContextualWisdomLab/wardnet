//! End-to-end coverage for the `main.rs` shim and shutdown path.
//!
//! Spawns the real gateway binary, waits until it reports readiness (proving it
//! bound the listener), then stops it with the platform-appropriate mechanism.
//! Running the binary under `cargo llvm-cov` records coverage for `main.rs` and
//! `shutdown_signal`, which cannot be reached from in-process unit tests.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

#[test]
#[cfg(unix)]
fn binary_serves_then_shuts_down_on_sigterm() {
    let mut child = spawn_ready_gateway();

    // SIGTERM drives the graceful-shutdown path so the process exits cleanly
    // (and flushes coverage counters) instead of being force-killed.
    let signalled = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(signalled.success(), "failed to deliver SIGTERM");

    let exit = child.wait().expect("await gateway exit");
    assert!(
        exit.success(),
        "gateway should exit cleanly on SIGTERM: {exit:?}"
    );
}

#[test]
#[cfg(not(unix))]
fn binary_serves_until_force_stopped_on_windows() {
    let mut child = spawn_ready_gateway();
    child.kill().expect("force-stop gateway binary");
    let exit = child.wait().expect("await gateway exit");
    assert!(
        !exit.success(),
        "forced Windows shutdown should not masquerade as graceful: {exit:?}"
    );
}

#[test]
fn binary_does_not_report_readiness_before_state_validation() {
    let state_path = std::env::temp_dir().join(format!(
        "wardnet-corrupt-state-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    std::fs::write(&state_path, "not-json").expect("write corrupt state fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "127.0.0.1:0")
        .env("WAF_IDS_STATE_PATH", &state_path)
        .env_remove("ADMIN_TOKEN")
        .env_remove("ADMIN_TOKENS")
        .env_remove("WAF_IDS_CREDENTIALS_PATH")
        .env_remove("CORAZA_LIB_PATH")
        .env_remove("CORAZA_RULES_PATH")
        .env_remove("CORAZA_DIRECTIVES")
        .env_remove("CONTROL_PLANE_DATABASE_URL")
        .output()
        .expect("spawn gateway binary for startup validation check");
    let _ = std::fs::remove_file(&state_path);

    assert!(
        !output.status.success(),
        "corrupt state must fail startup: {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("is not valid JSON"),
        "startup error should explain the invalid state file:\n{combined}"
    );
    assert!(
        !combined.contains("waf-ids-ai-soc listening on"),
        "readiness must not be reported until persisted state validates:\n{combined}"
    );
}

#[test]
fn binary_fail_closes_when_libcoraza_path_is_missing() {
    let output = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "127.0.0.1:0")
        .env("CORAZA_LIB_PATH", "/no/such/libcoraza.so")
        .env("CORAZA_DIRECTIVES", "SecRuleEngine On")
        .env_remove("WAF_IDS_STATE_PATH")
        .env_remove("ADMIN_TOKEN")
        .env_remove("ADMIN_TOKENS")
        .output()
        .expect("spawn gateway binary for libcoraza path check");
    assert!(
        !output.status.success(),
        "missing libcoraza must fail startup: {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("CORAZA_LIB_PATH") || combined.contains("does not exist"),
        "startup error should name the missing library:\n{combined}"
    );
    assert!(
        !combined.contains("waf-ids-ai-soc listening on"),
        "readiness must not be reported when libcoraza cannot load:\n{combined}"
    );
}

#[test]
fn binary_fail_closes_non_loopback_listen_without_postgres() {
    let output = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "0.0.0.0:0")
        .env_remove("CONTROL_PLANE_DATABASE_URL")
        .env_remove("WAF_IDS_STATE_PATH")
        .env_remove("ADMIN_TOKEN")
        .env_remove("ADMIN_TOKENS")
        .env_remove("CORAZA_LIB_PATH")
        .output()
        .expect("spawn gateway binary for production postgres gate");
    assert!(
        !output.status.success(),
        "production bind without postgres must fail: {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("CONTROL_PLANE_DATABASE_URL"),
        "startup error should name the missing control plane:\n{combined}"
    );
    assert!(
        !combined.contains("waf-ids-ai-soc listening on"),
        "readiness must not be reported without production postgres:\n{combined}"
    );
}

#[test]
fn binary_fail_closes_when_control_plane_sslmode_is_ambiguous() {
    let output = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "127.0.0.1:0")
        .env(
            "CONTROL_PLANE_DATABASE_URL",
            "postgres://wardnet@127.0.0.1/wardnet?sslmode=prefer",
        )
        .env_remove("WAF_IDS_STATE_PATH")
        .env_remove("CORAZA_LIB_PATH")
        .output()
        .expect("spawn gateway binary for sslmode check");
    assert!(
        !output.status.success(),
        "sslmode=prefer must fail startup: {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("sslmode"),
        "startup error should name the rejected sslmode:\n{combined}"
    );
    assert!(
        !combined.contains("waf-ids-ai-soc listening on"),
        "readiness must not be reported for an ambiguous sslmode:\n{combined}"
    );
}

#[test]
fn binary_fail_closes_when_control_plane_url_is_not_postgres() {
    let output = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "127.0.0.1:0")
        .env("CONTROL_PLANE_DATABASE_URL", "mysql://not-postgres")
        .env_remove("WAF_IDS_STATE_PATH")
        .env_remove("CORAZA_LIB_PATH")
        .output()
        .expect("spawn gateway binary for control-plane URL check");
    assert!(
        !output.status.success(),
        "non-postgres URL must fail startup: {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("postgres://"),
        "startup error should require a postgres URL:\n{combined}"
    );
    assert!(
        !combined.contains("waf-ids-ai-soc listening on"),
        "readiness must not be reported for a rejected control-plane URL:\n{combined}"
    );
}

fn spawn_ready_gateway() -> Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "127.0.0.1:0")
        .env_remove("WAF_IDS_STATE_PATH")
        .env_remove("EVENT_LIMIT")
        .env_remove("RATE_LIMIT")
        .env_remove("RATE_LIMIT_WINDOW")
        .env_remove("MAX_BODY_BYTES")
        .env_remove("CORAZA_LIB_PATH")
        .env_remove("CORAZA_RULES_PATH")
        .env_remove("CORAZA_DIRECTIVES")
        .env_remove("CORAZA_WAF_URL")
        .env_remove("CONTROL_PLANE_DATABASE_URL")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn gateway binary");

    // Block until the readiness line is printed, proving the listener bound.
    let stdout = child.stdout.take().expect("captured stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read readiness line");
    assert!(
        line.contains("listening on"),
        "unexpected startup line: {line:?}"
    );
    child
}

#[test]
fn release_checksums_script_emits_sha256_lines() {
    let dir = std::env::temp_dir().join(format!("wardnet-checksums-{}", std::process::id()));
    let nested = dir.join("dist");
    std::fs::create_dir_all(&nested).expect("temp dir");
    let artifact = nested.join("waf-ids-ai-soc-linux-x86_64");
    std::fs::write(&artifact, b"wardnet-release-fixture").expect("write fixture");
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/release-checksums.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg(&artifact)
        .output()
        .expect("run release-checksums.sh");
    assert!(
        output.status.success(),
        "checksums script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().expect("one checksum line");
    let digest = line.split_whitespace().next().expect("hex digest");
    assert_eq!(digest.len(), 64, "SHA-256 hex: {line}");
    assert!(
        digest.chars().all(|ch| ch.is_ascii_hexdigit()),
        "digest must be hex: {digest}"
    );
    assert!(
        line.contains("waf-ids-ai-soc-linux-x86_64"),
        "checksum line must name the artifact: {line}"
    );
    assert!(
        !line.contains("dist/"),
        "SHA256SUMS must use basenames so sha256sum -c works next to the download: {line}"
    );
    let sums = nested.join("SHA256SUMS");
    std::fs::write(&sums, stdout.as_bytes()).expect("write SHA256SUMS");
    let verified = if Command::new("sha256sum").arg("--version").output().is_ok() {
        Command::new("sha256sum")
            .current_dir(&nested)
            .args(["-c", "SHA256SUMS"])
            .output()
            .expect("sha256sum -c")
    } else {
        Command::new("shasum")
            .current_dir(&nested)
            .args(["-a", "256", "-c", "SHA256SUMS"])
            .output()
            .expect("shasum -c")
    };
    assert!(
        verified.status.success(),
        "checksum file must verify: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn release_sbom_script_fails_closed_without_syft() {
    let dir = std::env::temp_dir().join(format!("wardnet-sbom-missing-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let artifact = dir.join("artifact.bin");
    std::fs::write(&artifact, b"wardnet-sbom-fixture").expect("write fixture");
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/release-sbom.sh");
    let empty_path = dir.join("empty-path");
    std::fs::create_dir_all(&empty_path).expect("empty PATH dir");
    let output = Command::new("/bin/bash")
        .arg(&script)
        .arg("--output")
        .arg(dir.join("sbom.spdx.json"))
        .arg(&artifact)
        .env("PATH", &empty_path)
        .output()
        .expect("run release-sbom.sh without syft");
    assert!(
        !output.status.success(),
        "SBOM script must fail closed without syft"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("syft is required"),
        "operator-visible fail-closed: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn release_sbom_script_rejects_non_spdx_and_accepts_spdx_json() {
    let dir = std::env::temp_dir().join(format!("wardnet-sbom-stub-{}", std::process::id()));
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).expect("stub PATH");
    let artifact = dir.join("artifact.bin");
    std::fs::write(&artifact, b"wardnet-sbom-fixture").expect("write fixture");
    let syft = bin.join("syft");
    std::fs::write(
        &syft,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
for arg in "$@"; do
  case "$arg" in
    spdx-json=*) out="${arg#spdx-json=}" ;;
  esac
done
if [[ -z "$out" ]]; then
  echo "stub syft expected -o spdx-json=FILE" >&2
  exit 1
fi
mode="${STUB_SYFT_MODE:-spdx}"
if [[ "$mode" == "garbage" ]]; then
  printf '{"not":"spdx"}\n' > "$out"
else
  printf '{"spdxVersion":"SPDX-2.3","packages":[{"name":"waf-ids-ai-soc"}]}\n' > "$out"
fi
"#,
    )
    .expect("write stub syft");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&syft)
            .expect("stub metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&syft, permissions).expect("chmod stub");
    }
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/release-sbom.sh");
    let mut path = std::env::var("PATH").unwrap_or_default();
    path = format!("{}:{path}", bin.display());
    let garbage = Command::new("bash")
        .arg(&script)
        .arg("--output")
        .arg(dir.join("bad.spdx.json"))
        .arg(&artifact)
        .env("PATH", &path)
        .env("STUB_SYFT_MODE", "garbage")
        .output()
        .expect("run release-sbom.sh garbage");
    assert!(
        !garbage.status.success(),
        "non-SPDX JSON must fail closed: {}",
        String::from_utf8_lossy(&garbage.stderr)
    );
    let good_out = dir.join("sbom.spdx.json");
    let good = Command::new("bash")
        .arg(&script)
        .arg("--output")
        .arg(&good_out)
        .arg(&artifact)
        .env("PATH", &path)
        .env("STUB_SYFT_MODE", "spdx")
        .output()
        .expect("run release-sbom.sh spdx");
    assert!(
        good.status.success(),
        "SPDX JSON must be accepted: {}",
        String::from_utf8_lossy(&good.stderr)
    );
    let body = std::fs::read_to_string(&good_out).expect("read SPDX");
    assert!(body.contains("SPDX-2.3"), "SPDX version: {body}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn release_workflow_is_keyless_and_signs_by_digest() {
    let workflow = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release.yml"),
    )
    .expect("read release.yml");
    assert!(workflow.contains("id-token: write"));
    assert!(workflow.contains("attestations: write"));
    assert!(workflow.contains("cosign sign --yes"));
    assert!(workflow.contains("cosign sign-blob --yes"));
    assert!(workflow.contains("scripts/release-sbom.sh"));
    assert!(workflow.contains("attest-build-provenance"));
    assert!(
        !workflow.contains(":latest"),
        "must not push a moving latest tag"
    );
    assert!(
        workflow.contains("--verify-tag"),
        "GitHub Release must verify the tag"
    );
}
