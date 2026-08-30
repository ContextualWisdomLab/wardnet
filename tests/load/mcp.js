import http from "k6/http";
import { check } from "k6";

const endpoint = `${__ENV.WARDNET_URL || "http://127.0.0.1:3000"}/mcp`;
const token = __ENV.WARDNET_ADMIN_TOKEN;

if (!token || !token.trim()) {
  throw new Error("WARDNET_ADMIN_TOKEN is required");
}

export const options = {
  thresholds: {
    checks: ["rate==1"],
    http_req_failed: ["rate==0"],
  },
};

export default function () {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: `${__VU}-${__ITER}`,
    method: "tools/call",
    params: {
      name: "wardnet_status",
      arguments: {},
      _meta: {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      },
    },
  });
  const response = http.post(endpoint, body, {
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
      "MCP-Protocol-Version": "2026-07-28",
      "Mcp-Method": "tools/call",
      "Mcp-Name": "wardnet_status",
      "X-Admin-Token": token,
    },
  });
  check(response, {
    "status tool returns a complete structured result": (result) => {
      if (result.status !== 200) return false;
      const value = result.json();
      return (
        value.result?.resultType === "complete" &&
        value.result?.isError === false &&
        value.result?.structuredContent?.health?.status === "ok"
      );
    },
  });
}
