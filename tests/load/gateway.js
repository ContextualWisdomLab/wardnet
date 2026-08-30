import http from "k6/http";
import { check } from "k6";

const baseUrl = __ENV.WARDNET_BASE_URL;

if (!baseUrl) {
  throw new Error("WARDNET_BASE_URL is required");
}

export const options = {
  vus: Number(__ENV.K6_VUS || 32),
  duration: __ENV.K6_DURATION || "30s",
  noConnectionReuse: __ENV.K6_CLOSE_CONNECTIONS === "true",
  thresholds: {
    checks: ["rate==1"],
    http_req_failed: ["rate==0"],
  },
};

export default function () {
  const response = http.get(`${baseUrl}/gateway/demo/load`, {
    headers: { "x-forwarded-for": `198.51.100.${(__VU % 200) + 1}` },
  });
  check(response, {
    "gateway returns 200": (result) => result.status === 200,
    "gateway executes the monitored route": (result) => {
      const body = result.json();
      return body.action === "monitored" && body.route_id === "demo";
    },
  });
}
