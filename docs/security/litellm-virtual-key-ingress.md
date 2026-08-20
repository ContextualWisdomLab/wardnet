# LiteLLM virtual-key ingress defense

## Protected failure

The Wardnet `litellm-virtual-key-proxy` binary rejects the following request before it reaches LiteLLM:

```text
Authorization: Bearer 061012345318
```

The proxy requires exactly one Bearer credential with a bounded LiteLLM virtual-key shape beginning `sk-`. It does **not** transform a phone number, account identifier, provider-native API key, or arbitrary string into a virtual key.

## Trust boundary

```text
Caller
  │ untrusted Authorization header
  ▼
Wardnet litellm-virtual-key-proxy
  ├─ bounded request body
  ├─ LiteLLM credential-class guard
  ├─ approved request-header projection
  ├─ fixed HTTPS upstream / no redirects
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

## Deployment configuration

Run the dedicated binary with one fixed upstream:

```bash
LITELLM_UPSTREAM_URL=https://llm-gateway-dev.hyosungitx.com \
LITELLM_PROXY_BIND_ADDR=0.0.0.0:8090 \
LITELLM_MAX_BODY_BYTES=16777216 \
LITELLM_CONNECT_TIMEOUT_SECONDS=10 \
cargo run --locked --bin litellm-virtual-key-proxy
```

Environment contract:

| Variable | Required | Meaning |
|---|---:|---|
| `LITELLM_UPSTREAM_URL` | yes | Fixed LiteLLM base URL; HTTPS required except loopback tests |
| `LITELLM_PROXY_BIND_ADDR` | no | Listen address, default `127.0.0.1:8090` |
| `LITELLM_MAX_BODY_BYTES` | no | Positive request-body bound, default 16 MiB |
| `LITELLM_CONNECT_TIMEOUT_SECONDS` | no | Positive upstream connect timeout, default 10 seconds |

Clients call the Wardnet listener with the original OpenAI-compatible path:

```text
POST https://wardnet-llm.example/v1/chat/completions
Authorization: Bearer sk-...
```

The proxy appends the incoming path and query to the fixed upstream base. An upstream URL containing credentials, a query, or a fragment is rejected. Redirect following is disabled so a configured endpoint cannot redirect the accepted key to a second host.

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
- request and W3C trace correlation headers
- `x-litellm-*` extension headers

It does not forward cookies, `Host`, forwarding-chain headers, proxy credentials, `Connection`, transfer framing, or arbitrary caller headers.

Approved upstream response metadata includes content type/encoding, retry information, authentication challenge, request correlation, OpenAI/LiteLLM metadata, and rate-limit headers. Response bodies are streamed rather than accumulated in memory, preserving server-sent event behavior and bounding proxy memory by active chunks rather than full completions.

## Health contract

`GET /healthz` does not require an LLM key. It exposes only:

- service status;
- credential policy name;
- upstream origin without credentials, query, or path details;
- configured request-body bound.

It does not test a billable model call or reveal a virtual key.

## Operational diagnosis

When `llm_auth_rejected` increases:

1. Identify the caller from trusted edge identity or deployment audit context, not from the rejected token.
2. Inspect the caller's credential-selection configuration.
3. Confirm it references a LiteLLM virtual-key secret, not a phone number, user ID, billing account, or provider-native key.
4. Rotate or remap the secret at its owning credential registry.
5. Test one request through Wardnet.
6. Confirm the request reaches LiteLLM and that LiteLLM performs its own key authorization.

Never resolve the alert by bypassing the proxy, logging the complete header, or automatically adding the `sk-` prefix.

## Verification matrix

| Case | Expected result |
|---|---|
| Health request | 200 without Authorization; no upstream request |
| Missing Authorization | 401; no upstream request |
| Two Authorization headers | 401; no upstream request |
| `Basic ...` | 401; no upstream request |
| `Bearer 0610...` | 401; no token reflection; secret-free structured event |
| Invalid token character or misplaced padding | 401 |
| Bounded `Bearer sk-...` | Forwarded for authoritative LiteLLM validation |
| Cookie supplied with valid key | Cookie stripped |
| Query string supplied | Preserved on the fixed upstream path |
| SSE upstream response | Streamed with content type and rate-limit metadata |
| Upstream redirect | Returned to the caller; not followed with the credential |
