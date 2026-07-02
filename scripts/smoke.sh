#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
STATE_FILE="$TMP_DIR/state.json"
LOG_FILE="$TMP_DIR/server.log"
ADMIN_TOKEN_VALUE="dev-secret"
PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
BASE_URL="http://127.0.0.1:$PORT"
SERVER_PID=""

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

start_server() {
  (
    cd "$ROOT_DIR"
    BIND_ADDR="127.0.0.1:$PORT" \
      ADMIN_TOKEN="$ADMIN_TOKEN_VALUE" \
      WAF_IDS_STATE_PATH="$STATE_FILE" \
      DNSBL_ORIGIN="dnsbl.test" \
      EVENT_LIMIT="5" \
      cargo run --quiet
  ) >"$LOG_FILE" 2>&1 &
  SERVER_PID="$!"

  for _ in $(seq 1 80); do
    if curl -fsS "$BASE_URL/healthz" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      cat "$LOG_FILE" >&2
      echo "server exited before health check passed" >&2
      exit 1
    fi
    sleep 0.25
  done

  cat "$LOG_FILE" >&2
  echo "server did not become healthy" >&2
  exit 1
}

assert_json_field() {
  local json="$1"
  local expression="$2"
  JSON_INPUT="$json" python3 - "$expression" <<'PY'
import json
import os
import sys

data = json.loads(os.environ["JSON_INPUT"])
expression = sys.argv[1]
if not eval(expression, {"__builtins__": {"any": any}}, {"data": data}):
    raise SystemExit(f"assertion failed: {expression}; data={data!r}")
PY
}

start_server

health="$(curl -fsS "$BASE_URL/healthz")"
assert_json_field "$health" 'data["status"] == "ok"'
assert_json_field "$health" 'data["persistence"] == "file"'
assert_json_field "$health" 'data["dnsbl_origin"] == "dnsbl.test"'
assert_json_field "$health" 'data["event_limit"] == 5'

curl -fsS "$BASE_URL/admin" | grep -q "ContextualWisdomLab WAF/IDS/AI SOC Gateway"

unauthorized_code="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "$BASE_URL/api/routes" \
    -H 'content-type: application/json' \
    -d '{"id":"block","path_prefix":"/block","upstream":"mock://block","mode":"block","enabled":true}'
)"
test "$unauthorized_code" = "401"

curl -fsS \
  -X POST "$BASE_URL/api/routes" \
  -H 'content-type: application/json' \
  -H "x-admin-token: $ADMIN_TOKEN_VALUE" \
  -d '{"id":"block","path_prefix":"/block","upstream":"mock://block","mode":"block","enabled":true}' \
  >/dev/null

blocked_code="$(
  curl -sS -o "$TMP_DIR/blocked.json" -w '%{http_code}' \
    "$BASE_URL/gateway/block?q=union%20select"
)"
test "$blocked_code" = "403"
grep -q '"action":"blocked"' "$TMP_DIR/blocked.json"

kpis="$(curl -fsS "$BASE_URL/api/kpis")"
assert_json_field "$kpis" 'data["blocked_event_count"] >= 1'
assert_json_field "$kpis" 'data["event_count"] >= 1'

zone="$(curl -fsS "$BASE_URL/dnsbl/zone")"
grep -q '^\$ORIGIN dnsbl.test\.$' <<<"$zone"
grep -q '^10.113.0.203 IN A 127.0.0.2$' <<<"$zone"

kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

start_server
routes="$(curl -fsS "$BASE_URL/api/routes")"
assert_json_field "$routes" 'any(route["id"] == "block" for route in data)'

echo "smoke ok: $BASE_URL with state $STATE_FILE"
