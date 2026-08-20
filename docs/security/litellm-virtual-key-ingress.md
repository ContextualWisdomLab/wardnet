# LiteLLM virtual-key ingress defense

## Protected failure

The Wardnet `litellm-virtual-key-proxy` binary rejects a telephone-shaped synthetic credential before it reaches LiteLLM:

```text
Authorization: Bearer 01000000000
```

The proxy requires exactly one Bearer credential with a bounded LiteLLM virtual-key shape beginning `sk-`. It does **not** transform a telephone number, account identifier, provider-native API key, or arbitrary string into a virtual key.

## Trust boundary

```text
Caller
  │ untrusted Authorization header
  ▼
Wardnet litellm-virtual-key-proxy
  ├─ bounded request body
  ├─ bounded LiteLLM credential-class guard
  ├─ approved request-header projection
  ├─ fixed HTTPS origin / no system proxy / no redirects
  └─ streaming response relay
       │ accepted Bearer value
       ▼
LiteLLM
  ├─ key existence and revocation
  ├─ team / user / model scope
  ├─ quota and budget
  └─ provider routing
```

The Wardnet guard establishes only a lexical class boundary. A value such as `sk-not-a-real-key` can pass the edge shape check and must still fail LiteLLM authentication.

## Runtime configuration registry

Runtime values are read from a versioned JSON KV document and copied into an immutable process-local registry during startup. The only bootstrap input is the `--config <path>` argument. The proxy does not read individual runtime values from raw environment variables.

Copy the deployment example and restrict it to the `wardnet` service account:

```bash
install -o wardnet -g wardnet -m 0640 \
  deploy/systemd/litellm-virtual-key-proxy.json.example \
  /etc/wardnet/litellm-virtual-key-proxy.json
```

Example registry document:

```json
{
  "configuration_version": "1",
  "litellm_proxy_upstream_url": "https://gateway.example.invalid",
  "litellm_proxy_bind_address": "127.0.0.1:8090",
  "litellm_proxy_max_body_bytes": 16777216,
  "litellm_proxy_connect_timeout_seconds": 10
}
```

Run from source with:

```bash
cargo run --locked --bin litellm-virtual-key-proxy -- \
  --config ./deploy/systemd/litellm-virtual-key-proxy.json.example
```

The registry rejects unknown keys, wrong JSON types, unsupported `configuration_version` values, zero limits, and missing required values. A durable external KV can later materialize the same versioned JSON contract without changing the proxy's runtime lookup path.

## Upstream and request contract

Clients call the Wardnet listener with the original OpenAI-compatible path:

```text
POST https://wardnet-llm.example/v1/chat/completions
Authorization: Bearer sk-...
```

The configured upstream is an **origin**, not an arbitrary base path. Wardnet appends the incoming path and query to that fixed origin. An upstream URL containing credentials, a non-root path, query, or fragment is rejected. HTTPS is mandatory except for loopback integration tests. System proxy discovery and redirect following are disabled, and an upstream 3xx response is converted to a cache-safe `502 upstream_redirect_rejected` response without exposing `Location`.

Allowed methods are `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, and `OPTIONS`. `CONNECT`, `TRACE`, and extension methods fail with `405` before upstream I/O.

## Rejection contract

Wardnet returns:

- HTTP `401 Unauthorized`;
- `WWW-Authenticate: Bearer realm="litellm"` when the header is missing;
- an `invalid_token` challenge for duplicate headers, a non-Bearer scheme, or the wrong credential shape;
- `Cache-Control: no-store` and `Pragma: no-cache`;
- a stable JSON reason code with no submitted credential or masked fragment.

Structured rejection output uses:

```json
{
  "event_type": "llm_auth_rejected",
  "reason": "credential_shape_invalid",
  "path": "/v1/chat/completions"
}
```

Other reason codes are:

- `authorization_header_missing`
- `authorization_header_ambiguous`
- `authorization_scheme_invalid`
- `credential_shape_invalid`

Do not attach the rejected header to logs, traces, support bundles, alert messages, or exception details.

## Header boundary

Wardnet forwards only request metadata required by OpenAI-compatible LLM APIs:

- `Authorization`
- `Accept`
- `Content-Type` and `Content-Encoding`
- `User-Agent`
- OpenAI organization/project headers
- `X-Request-Id`
- W3C `traceparent` and `tracestate`

It does not forward cookies, `Host`, forwarding-chain headers, proxy credentials, `Connection`, transfer framing, trace `baggage`, arbitrary caller headers, or caller-controlled `x-litellm-*` extensions.

Approved upstream response metadata includes content type/encoding, retry information, authentication challenge, request correlation, OpenAI/LiteLLM response metadata, and rate-limit headers. Response bodies are streamed rather than accumulated in memory, preserving server-sent event behavior and bounding proxy memory by active chunks rather than full completions.

## Health contract

`GET /healthz` does not require an LLM key. It exposes only:

- service status;
- credential policy name;
- configuration contract version;
- fixed-upstream policy state without exposing the configured hostname;
- configured request-body bound.

It does not test a billable model call or reveal a virtual key.

## Operational diagnosis

When `llm_auth_rejected` increases:

1. Identify the caller from trusted edge identity or deployment audit context, not from the rejected token.
2. Inspect the caller's credential-selection configuration.
3. Confirm it references a LiteLLM virtual-key secret, not a telephone number, user ID, billing account, or provider-native key.
4. Rotate or remap the secret at its owning credential registry.
5. Test one request through Wardnet.
6. Confirm the request reaches LiteLLM and that LiteLLM performs its own key authorization.

Never resolve the alert by bypassing the proxy, logging the complete header, or automatically adding the `sk-` prefix.

## Verification matrix

| Case | Expected result |
|---|---|
| Health request | 200 without Authorization; no upstream request or configured hostname disclosure |
| Missing Authorization | 401; no upstream request |
| Two Authorization headers | 401; no upstream request |
| `Basic ...` | 401; no upstream request |
| Telephone-shaped synthetic Bearer value | 401; no token reflection; secret-free structured event |
| Header larger than the parser bound | Immediate 401 before delimiter scans |
| More than eight separator spaces | 401 |
| Non-ASCII value | 401 |
| Invalid token character or misplaced padding | 401 |
| Bounded `Bearer sk-...` | Forwarded for authoritative LiteLLM validation |
| Cookie or trace baggage supplied | Stripped |
| Query string supplied | Preserved on the fixed upstream path |
| Two-chunk SSE upstream response | Headers and first chunk relayed before final chunk release |
| `TRACE` or `CONNECT` | 405; no upstream request |
| Upstream redirect | 502; redirect target not returned or followed |
