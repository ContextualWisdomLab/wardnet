# Smoke gateway process ownership

## Observed defect

The smoke script built the gateway and started `cargo run` in a background
subshell. `SERVER_PID` therefore identified the launcher rather than necessarily
the serving gateway. Its stop sequence signalled that PID, waited for it, and
cleared the PID before restart. The exact retained `start_server` and stop
sequence was executed with real Cargo and the real gateway on a fixture-owned
loopback listener. After stop, `/healthz` still responded. The diagnostic exited
99 to preserve that failure and then terminated only its newly created process
group. No legacy/shared server was stopped.

This defect undermined restart evidence: the second startup could see the old
listener rather than a successfully restarted gateway. It also allowed a smoke
execution to leave its own gateway behind. Existing historical server PIDs are
not attributed to this defect without a matching producer identity.

## Minimal repair

Build the named gateway binary before the health wait, using Cargo's JSON
artifact stream. Select exactly one `compiler-artifact` with the gateway target
name and a non-null `executable` path. Cargo documents this path as the produced
executable, separately from the artifact filenames [1]. This avoids assuming
`target/debug`, ignoring `CARGO_TARGET_DIR`, or constructing a host binary path.

The background shell uses `exec env ... "$SERVER_BIN"`, retaining the existing
bootstrap values and log redirection. `SERVER_PID` now owns the actual gateway.
The existing SIGTERM/wait stop sequence and EXIT trap reach that process.
Neither the gateway's shutdown implementation nor production configuration is
changed. A repeated exact real-Cargo probe confirms that the old listener is
unreachable after stop and its diagnostic process group is empty.

The script retains `set -euo pipefail`: a failed build must stop startup even
if a partial artifact stream contains an executable. Missing, duplicate,
wrong-target and malformed artifact messages must also stop before execution.
The artifact parser is intentionally narrow and fails closed; arbitrary supplier
stdout is not silently accepted as an executable identity.

## Retained regression and limits

`tests/smoke_process_lifecycle.rs` executes the shipped shell prefix and real
Cargo-built gateway. During Cargo tests only artifact discovery is an explicit
synthetic command fixture, because recursively building the same target would
contend with the invoking Cargo lock. The complete smoke run and separate
RED/GREEN diagnostics retain actual Cargo execution as a distinct obligation.

The lifecycle regression verifies direct-process reaping and listener closure,
a successful restart, and cleanup after a deliberate later shell failure. It
requires the second gateway PID to be absent and the temporary state directory
to be removed. Five offline artifact rejection controls require zero gateway
execution. Diagnostic timeouts and process-group cleanup apply only to newly
created fixture resources, never other owners or production services.

Under instrumented test execution, the lifecycle fixture forwards only
`LLVM_PROFILE_FILE` from its parent into the otherwise explicit child-environment
allowlist. Without that route, the real gateway wrote default profiles outside
the collector and its two executions were omitted. The fixture still discards
ambient credentials and application configuration. A configured-route regression
and a full instrumented workspace replay verify the route; test success alone
is not proof of profile collection. Collection completeness does not raise or
waive the original 100% coverage requirement.

Unix SIGTERM/reaping behavior is covered by the Unix regression. Other platforms,
hosted runner execution, arbitrary escaped descendants and a stalled graceful
shutdown are not certified by this test. Passing smoke is not protected merge,
release acceptance, complete coverage, or whole-product completion. Original
dirty files, legacy server processes and other worktrees remain outside scope.

## Reference

[1] The Rust Project. *The Cargo Book: External tools*, JSON messages and
artifact messages (`compiler-artifact`, `target`, `executable`).
https://doc.rust-lang.org/cargo/reference/external-tools.html
