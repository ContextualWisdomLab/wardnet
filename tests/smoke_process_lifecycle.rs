//! Exercise the shipped launch/stop/EXIT cleanup with the real gateway binary.
//! Cargo artifact discovery is an explicit offline fixture during Cargo tests:
//! recursively building the same target would contend for Cargo's own lock.

#[test]
fn smoke_rejects_failed_or_ambiguous_cargo_artifact_discovery() {
    use std::process::Command;

    let output = Command::new("python3")
        .args([
            "-B",
            "-c",
            r#"
import json, os, pathlib, subprocess, sys, tempfile
script_path, scratch = map(pathlib.Path, sys.argv[1:])
sys.path.insert(0, str(script_path.parent.parent / 'tests' / 'support'))
from smoke_subtree import owned_root, run as run_subtree
script = script_path.read_text()
prefix = script.split('\nstart_server\n', 1)[0]
prefix = prefix.replace('ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"', 'ROOT_DIR="$OWNED_ROOT"')
with owned_root(prefix='wardnet cargo artifact ', dir=scratch) as directory:
    root = pathlib.Path(directory)
    tools = root / 'tools'; tools.mkdir()
    sentinel = tools / 'gateway'
    sentinel.write_text('#!/bin/sh\n: > "$EXECUTION_SENTINEL"\nexit 0\n'); sentinel.chmod(0o700)
    artifact = {'reason': 'compiler-artifact', 'target': {'name': 'waf-ids-ai-soc'}, 'executable': str(sentinel)}
    cases = [
        ('failed build with valid artifact', json.dumps(artifact), 42),
        ('missing artifact', json.dumps({'reason': 'build-finished', 'success': True}), 0),
        ('duplicate artifact', json.dumps(artifact) + '\n' + json.dumps(artifact), 0),
        ('wrong target', json.dumps(dict(artifact, target={'name': 'unrelated'})), 0),
        ('malformed JSON', '{broken', 0),
    ]
    for name, payload, exit_code in cases:
        cargo = tools / 'cargo'
        cargo.write_text('#!/bin/sh\nprintf "%s\\n" "$ARTIFACT_BYTES"\nexit "$ARTIFACT_EXIT"\n'); cargo.chmod(0o700)
        env = {'PATH': str(tools) + os.pathsep + os.defpath + os.pathsep + '/opt/homebrew/bin',
               'TMPDIR': str(root), 'OWNED_ROOT': str(script_path.parent.parent),
               'ARTIFACT_BYTES': payload, 'ARTIFACT_EXIT': str(exit_code),
               'EXECUTION_SENTINEL': str(root / 'executed')}
        driver = prefix + '\nstart_server\necho UNEXPECTED_START_SUCCESS\n'
        # Hang guard only: each case starts several python3 processes, and on a
        # loaded host one case measured 3-7 s wall time, so 6 s was load-flaky.
        result = run_subtree(['bash', '-s'], input=driver.encode(), env=env,
                             timeout=60, root=root)
        assert result.returncode != 0, (name, 'failed discovery passed')
        assert not (root / 'executed').exists(), (name, 'binary executed before build acceptance')
        assert b'UNEXPECTED_START_SUCCESS' not in result.stdout, name
    print('five artifact rejection controls passed; no gateway executed')
"#,
            concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/smoke.sh"),
            std::env::temp_dir().to_str().unwrap(),
        ])
        .output()
        .expect("run offline artifact-discovery controls");
    assert!(
        output.status.success(),
        "artifact discovery contract failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[cfg(unix)]
fn smoke_subtree_settlement_controls() {
    let output = std::process::Command::new("python3")
        .args([
            "-B",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/support/test_smoke_subtree.py"
            ),
            "-v",
        ])
        .env("TMPDIR", std::env::temp_dir())
        .output()
        .expect("run native subtree settlement controls");
    assert!(
        output.status.success(),
        "subtree controls failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[cfg(unix)]
fn smoke_owns_and_reaps_the_gateway_on_stop_restart_and_exit() {
    use std::process::Command;

    let output = Command::new("python3")
        .args([
            "-c",
            r#"
import json, os, pathlib, signal, subprocess, sys, tempfile, time

script_path, binary, scratch = map(pathlib.Path, sys.argv[1:])
script = script_path.read_text()
prefix = script.split('\nstart_server\n', 1)[0]
prefix = prefix.replace('ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"', 'ROOT_DIR="$OWNED_ROOT"')
assert 'start_server()' in prefix and 'trap cleanup EXIT' in prefix

with tempfile.TemporaryDirectory(prefix='wardnet smoke lifecycle ', dir=scratch) as fixture:
    root = pathlib.Path(fixture)
    tools = root / 'tools'
    tools.mkdir()
    cargo = tools / 'cargo'
    cargo.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$OWNED_CARGO_ARGS"\nprintf "%s\\n" "$OWNED_CARGO_ARTIFACT"\n')
    cargo.chmod(0o700)
    env = {
        'PATH': str(tools) + os.pathsep + os.defpath + os.pathsep + '/opt/homebrew/bin',
        'TMPDIR': str(root),
        'OWNED_ROOT': str(script_path.parent.parent),
        'OWNED_CARGO_ARGS': str(root / 'cargo-args'),
        'OWNED_CARGO_ARTIFACT': json.dumps({'reason': 'compiler-artifact', 'target': {'name': 'waf-ids-ai-soc'}, 'executable': str(binary)}),
        'NO_PROXY': '127.0.0.1',
    }
    if 'LLVM_PROFILE_FILE' in os.environ:
        # Preserve only the profiler's output route, not ambient credentials or
        # application configuration discarded by the fixture's allowlist.
        env['LLVM_PROFILE_FILE'] = os.environ['LLVM_PROFILE_FILE']
        assert env.get('LLVM_PROFILE_FILE') == os.environ['LLVM_PROFILE_FILE'], 'lifecycle fixture dropped coverage output routing'
    driver = prefix + '''
start_server
FIRST_PID="$SERVER_PID"
printf 'FIRST_PID=%s\n' "$FIRST_PID"
kill "$SERVER_PID"
wait "$SERVER_PID"
SERVER_PID=""
if kill -0 "$FIRST_PID" 2>/dev/null; then exit 91; fi
if curl -fsS "$BASE_URL/healthz" >/dev/null 2>&1; then exit 92; fi
start_server
printf 'SECOND_PID=%s\n' "$SERVER_PID"
printf 'LISTENER=%s\n' "$BASE_URL"
printf 'STATE_ROOT=%s\n' "$TMP_DIR"
# Deliberately fail a later assertion: the EXIT trap must still stop the server.
exit 37
'''
    p = subprocess.Popen(['bash', '-s'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env, start_new_session=True)
    try:
        stdout, stderr = p.communicate(driver.encode(), timeout=30)
        markers = dict(line.split('=', 1) for line in stdout.decode().splitlines() if '=' in line)
        assert p.returncode == 37, ('stop/restart did not settle', p.returncode, stderr.decode())
        assert 'FIRST_PID' in markers and 'SECOND_PID' in markers
        for key in ['FIRST_PID', 'SECOND_PID']:
            try:
                os.kill(int(markers[key]), 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError('owned gateway survived: ' + key)
        health = subprocess.run(['curl', '-fsS', '--max-time', '2', markers['LISTENER'] + '/healthz'],
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        assert health.returncode != 0, 'EXIT cleanup left its listener serving'
        assert not pathlib.Path(markers['STATE_ROOT']).exists(), 'EXIT cleanup left its owned state directory'
        args = (root / 'cargo-args').read_text().splitlines()
        assert args == ['build', '--quiet', '--manifest-path', str(script_path.parent.parent / 'Cargo.toml'),
                        '--bin', 'waf-ids-ai-soc', '--message-format=json'], args
        print(json.dumps({'stop': 'reaped', 'restart': 'ready', 'exit_cleanup': 'reaped',
                          'listener': 'unreachable', 'state_directory': 'removed',
                          'cargo': 'fixture artifact discovery', 'binary': 'actual gateway'}))
    finally:
        # Scope is this newly created process group, never legacy/shared servers.
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(timeout=3)
        deadline = time.monotonic() + 3
        while True:
            try:
                os.killpg(p.pid, 0)
            except ProcessLookupError:
                break
            if time.monotonic() >= deadline:
                os.killpg(p.pid, signal.SIGKILL)
                raise AssertionError('diagnostic required forced descendant cleanup')
            time.sleep(0.01)
"#,
            concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/smoke.sh"),
            env!("CARGO_BIN_EXE_waf-ids-ai-soc"),
            std::env::temp_dir().to_str().unwrap(),
        ])
        .output()
        .expect("run owned lifecycle fixture");
    assert!(
        output.status.success(),
        "smoke lifecycle contract failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
