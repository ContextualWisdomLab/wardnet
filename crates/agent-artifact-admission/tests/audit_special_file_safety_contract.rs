#![cfg(target_os = "linux")]

use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use wardnet_agent_artifact_admission::{
    AdmissionPolicy, AuditError, AuditRecord, AuditSink, FileAuditSink, InstallIntent,
    admission_decision, build_audit_record,
};

const FIFO_HELPER_PATH: &str = "WARDNET_AUDIT_FIFO_HELPER_PATH";
const HELPER_DEADLINE: Duration = Duration::from_secs(3);

fn temp_path(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "wardnet-agent-admission-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn blocked_record() -> AuditRecord {
    let intent = InstallIntent::unowned_llms_package_for_test();
    let decision = admission_decision(&AdmissionPolicy::deny_all_for_test(), &intent);
    build_audit_record(&intent, &decision).expect("audit record must build")
}

#[test]
fn file_sink_rejects_fifo_without_blocking_on_open() {
    let fifo_path = temp_path("audit-fifo");
    let mkfifo = Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .expect("mkfifo must be available on the Linux test runner");
    assert!(mkfifo.success(), "FIFO fixture must be created");

    let executable = std::env::current_exe().expect("current test executable must resolve");
    let mut child = Command::new(executable)
        .arg("--exact")
        .arg("audit_fifo_open_helper")
        .arg("--nocapture")
        .env(FIFO_HELPER_PATH, &fifo_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("isolated FIFO helper must start");

    let deadline = Instant::now() + HELPER_DEADLINE;
    let status = loop {
        match child.try_wait().expect("FIFO helper status must be readable") {
            Some(status) => break Some(status),
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            None => break None,
        }
    };

    let _ = fs::remove_file(&fifo_path);

    match status {
        Some(status) => assert!(
            status.success(),
            "audit FIFO helper must reject the special file through the stable storage error"
        ),
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "audit append blocked while opening a FIFO; special audit files must fail closed promptly"
            );
        }
    }
}

#[test]
fn audit_fifo_open_helper() {
    let Ok(path) = std::env::var(FIFO_HELPER_PATH) else {
        return;
    };

    let result = FileAuditSink::new(path).append(&blocked_record());
    assert_eq!(result, Err(AuditError::StorageUnavailable));
}
