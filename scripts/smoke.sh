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
if not eval(expression, {"__builtins__": {"any": any, "len": len}}, {"data": data}):
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

curl -fsS \
  -X POST "$BASE_URL/api/commercial/license" \
  -H 'content-type: application/json' \
  -H "x-admin-token: $ADMIN_TOKEN_VALUE" \
  -d '{
    "tenant_id": "cwlab-enterprise",
    "deployment_id": "prod-seoul-edge",
    "edition": "enterprise",
    "license_status": "active",
    "license_id": "LIC-2B-KRW-0001",
    "licensee": "Contextual Wisdom Enterprise Buyer",
    "licensed_until_unix": 1829088000,
    "licensed_node_count": 12,
    "annual_contract_value_krw": 2000000000,
    "support_contact": "soc-support@example.com",
    "features": ["rust-edge-gateway", "tenant-license-readiness", "threat-feed-import", "dnsbl-zone-export"]
  }' \
  >/dev/null

curl -fsS \
  -X POST "$BASE_URL/api/threat-feeds/import" \
  -H 'content-type: application/json' \
  -H "x-admin-token: $ADMIN_TOKEN_VALUE" \
  -d '{
    "feed_id": "misp-seoul",
    "source": "misp://soc.example",
    "ttl_seconds": 600,
    "threats": [{
      "value": "credential_dump",
      "indicator_type": "malware",
      "severity": "critical",
      "source": "misp-seoul",
      "ttl_seconds": 600
    }],
    "dnsbl": [{
      "address": "198.51.100.23",
      "code": "127.0.0.4",
      "reason": "feed scanner",
      "source": "misp-seoul",
      "ttl_seconds": 600
    }]
  }' \
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
assert_json_field "$kpis" 'data["threat_feed_count"] == 1'
assert_json_field "$kpis" 'data["fresh_threat_feed_count"] == 1'
assert_json_field "$kpis" 'data["stale_threat_feed_count"] == 0'

readiness="$(curl -fsS "$BASE_URL/api/commercial/readiness")"
assert_json_field "$readiness" 'data["target_sale_value_krw"] == 2000000000'
assert_json_field "$readiness" 'data["ready_for_enterprise_sale"] is True'
assert_json_field "$readiness" 'data["readiness_level"] == "sale_ready"'
assert_json_field "$readiness" 'data["blockers"] == []'

feeds="$(curl -fsS "$BASE_URL/api/threat-feeds")"
assert_json_field "$feeds" 'len(data) == 1'
assert_json_field "$feeds" 'data[0]["feed_id"] == "misp-seoul"'
freshness="$(curl -fsS "$BASE_URL/api/threat-feeds/freshness")"
assert_json_field "$freshness" 'len(data) == 1'
assert_json_field "$freshness" 'data[0]["feed_id"] == "misp-seoul"'
assert_json_field "$freshness" 'data[0]["stale"] is False'

event_export="$(curl -fsS "$BASE_URL/api/events.ndjson")"
grep -q '"action":"blocked"' <<<"$event_export"

support_bundle="$(curl -fsS "$BASE_URL/api/support-bundle")"
assert_json_field "$support_bundle" 'data["readiness"]["ready_for_enterprise_sale"] is True'
assert_json_field "$support_bundle" 'data["commercial"]["annual_contract_value_krw"] == 2000000000'
assert_json_field "$support_bundle" 'data["kpis"]["fresh_threat_feed_count"] == 1'
assert_json_field "$support_bundle" 'data["threat_feed_freshness"][0]["stale"] is False'

zone="$(curl -fsS "$BASE_URL/dnsbl/zone")"
grep -q '^\$ORIGIN dnsbl.test\.$' <<<"$zone"
grep -q '^10.113.0.203 IN A 127.0.0.2$' <<<"$zone"
grep -q '^23.100.51.198 IN A 127.0.0.4$' <<<"$zone"

kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

start_server
routes="$(curl -fsS "$BASE_URL/api/routes")"
assert_json_field "$routes" 'any(route["id"] == "block" for route in data)'
license="$(curl -fsS "$BASE_URL/api/commercial/license")"
assert_json_field "$license" 'data["license_status"] == "active"'
feeds="$(curl -fsS "$BASE_URL/api/threat-feeds")"
assert_json_field "$feeds" 'len(data) == 1'

echo "smoke ok: $BASE_URL with state $STATE_FILE"
