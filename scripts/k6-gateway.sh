#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOAD_DIR="$(mktemp -d)"
LOG_FILE="$LOAD_DIR/wardnet.log"
PORT="$(python3 - <<'PY'
import socket

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
)"
BASE_URL="http://127.0.0.1:$PORT"
SERVER_PID=""

# shellcheck disable=SC2329 # invoked through the EXIT trap
cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$LOAD_DIR"
}
trap cleanup EXIT

command -v k6 >/dev/null || {
  echo "k6 is required" >&2
  exit 1
}

(cd "$ROOT_DIR" && cargo build --locked --quiet)

(
  cd "$ROOT_DIR"
  BIND_ADDR="127.0.0.1:$PORT" \
    EVENT_LIMIT="1000" \
    RATE_LIMIT="0" \
    CONTROL_PLANE_DATABASE_URL="" \
    exec target/debug/waf-ids-ai-soc
) >"$LOG_FILE" 2>&1 &
SERVER_PID="$!"

for _ in $(seq 1 120); do
  if curl -fsS "$BASE_URL/healthz" >/dev/null 2>&1; then
    WARDNET_BASE_URL="$BASE_URL" k6 run "$ROOT_DIR/tests/load/gateway.js"
    exit 0
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    cat "$LOG_FILE" >&2
    exit 1
  fi
  sleep 0.25
done

cat "$LOG_FILE" >&2
cp "$LOG_FILE" "$ROOT_DIR/target/k6-gateway-server.log"
echo "Wardnet did not become ready" >&2
exit 1
