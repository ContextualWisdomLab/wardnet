# Complete admin-response smoke verification

## Observed defect

The distributed `scripts/smoke.sh` checked the admin page with a pipeline:
`curl ... | grep -q ...` under `set -euo pipefail`. A matching title near the
start of the page can make `grep -q` exit before curl finishes writing the
response. A valid HTTP 200 page can then fail the smoke check with curl exit 23.
The curl error reference identifies 23 as a local write/callback error [1].

`tests/smoke_admin_response.rs` retrieves the actual application `/admin` bytes
through Axum. A fixture-owned loopback server sends the title-bearing first
8,192 bytes, waits 150 ms, and sends the rest. The unmodified shipped shell
check failed with exit 23 and empty stderr. After the minimal repair, the same
complete response passes and the captured file equals every application byte.

The earlier complete smoke execution also returned 23 with an empty log.
This controlled reproduction establishes a real defect in that consumer;
it does not retrospectively prove which command failed in the earlier run.
An initial test harness used a nonexistent `AppState::memory` constructor.
That compile error is retained separately and is not production RED evidence.

## Repair and preserved failure behavior

The harness downloads the complete response into its existing disposable
`TMP_DIR/admin.html`, then checks the title in that file. Curl must finish
successfully before grep runs. No HTTP or content validation is suppressed.
The existing temporary-directory cleanup also removes the downloaded page.

The regression executes the actual extracted shell block, not a reconstructed
implementation. A fixture path containing spaces exercises shell quoting.
Alongside the application-byte positive, controls require:

- complete HTTP 200 without the title: grep failure (1);
- HTTP 503 even with a title: curl HTTP failure (22);
- a title-bearing response shorter than its declared Content-Length: curl
  partial-transfer failure (18).

The meanings of curl 18 and 22 are documented in the same official reference
[1]. The test server, response framing, delays and error statuses are explicit
local fixtures, not observed deployed failures. Fixture deadlines bound this
regression; no global timeout, credential, provider, runner or protection
setting is changed.

## Accepted-socket fixture regression

A subsequent committed-head workspace execution failed in the fixture's request
read with `WouldBlock`, before any response was sent. The fixture used a
nonblocking listener and assumed the accepted stream would block. An owned
native macOS probe reproduced an immediate `WouldBlock` when a client connected
before sending headers; explicitly switching the accepted stream to blocking
mode allowed the same delayed request to be read within the existing timeout.
This is a test-fixture defect, not a new gateway or curl response defect.

The fixture now sets the accepted stream to blocking before applying its
unchanged two-second read/write timeouts. A test-owned loopback relay holds
request bytes for 150 ms after connecting, reproducing the original failure
without changing the extracted shipped curl check. The repaired test retains
complete-response success, truncated-response exit 18 and HTTP-error exit 22,
and joins the relay and server threads before reporting failure. Existing
accept and child deadlines remain in place; no global timeout is widened.
The initial committed-head failure and deterministic delayed-header RED are
retained separately from GREEN. No production shell or gateway change is
part of this fixture repair.

## Ownership and acceptance boundary

A historical alternative that buffers the complete response is already
preserved in the mixed-context Draft PR #95. That PR explicitly prohibits
mechanical aggregate adoption. This repair does not import its Coraza, egress,
database or release changes, alter another checkout, or claim the workaround
was newly invented. It adds a minimal causal fix on this owner's current branch
and an executable regression for the actual consumer boundary.

This check validates the admin page response and smoke consumer. It is not
pixel/accessibility/8-locale acceptance, an executed hosted job, protected merge,
release approval or a solution to runner capacity. Existing server processes
and original dirty files remain outside this repair's authority.

## Reference

[1] curl project. *libcurl error codes*: `CURLE_PARTIAL_FILE` (18),
`CURLE_HTTP_RETURNED_ERROR` (22), and `CURLE_WRITE_ERROR` (23).
https://curl.se/libcurl/c/libcurl-errors.html
