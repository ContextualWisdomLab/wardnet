# LiteLLM virtual-key ingress defense

## Protected failure

Wardnet can reject the following request before it reaches LiteLLM:

```text
Authorization: Bearer 061012345318
```

For a route configured with `authorization_policy: litellm_virtual_key`, the edge requires exactly one Bearer credential with a bounded LiteLLM virtual-key shape beginning `sk-`. It does **not** transform a phone number, account identifier, API key from another provider, or arbitrary string into a virtual key.

## Trust boundary

```text
Caller
  │ untrusted Authorization header
  ▼
Wardnet
  ├─ request admission / body bound
  ├─ LiteLLM credential-class guard
  ├─ WAF / IDS policy
  └─ approved-header reverse proxy
       │ accepted Bearer value
       ▼
LiteLLM
  ├─ key existence and revocation
  ├─ team / user / model scope
  ├─ quota and budget
  └─ provider routing
```

The Wardnet guard establishes only a lexical class boundary. A value such as `sk-not-a-real-key` can pass the edge shape check and must still fail LiteLLM authentication.

## Route configuration

Create a dedicated route instead of applying the policy to unrelated APIs:

```json
{
  "id": "litellm-dev",
  "path_prefix": "/llm",
  "upstream": "https://llm-gateway-dev.hyosungitx.com",
  "mode": "block",
  "enabled": true,
  "authorization_policy": "litellm_virtual_key"
}
```

Clients then call Wardnet, preserving the OpenAI-compatible suffix:

```text
POST https://wardnet.example/gateway/llm/v1/chat/completions
Authorization: Bearer sk-...
```

The upstream URL must also pass Wardnet's production destination-policy controls before internet-facing deployment. This feature does not close the broader SSRF and DNS-rebinding production blocker.

## Rejection contract

Wardnet returns:

- HTTP `401 Unauthorized`;
- `WWW-Authenticate: Bearer realm="litellm"` when the header is missing;
- an `invalid_token` challenge for duplicate headers, a non-Bearer scheme, or the wrong credential shape;
- `Cache-Control: no-store` and `Pragma: no-cache`;
- a stable JSON reason code with no submitted credential or masked fragment.

Security events use:

```json
{
  "action": "auth_rejected",
  "reason": "credential_shape_invalid"
}
```

Other reason codes are:

- `authorization_header_missing`
- `authorization_header_ambiguous`
- `authorization_scheme_invalid`
- `credential_shape_invalid`

Do not attach the rejected header to logs, traces, support bundles, alert messages, or exception details.

## Header boundary

Wardnet forwards only the request metadata needed by OpenAI-compatible LLM APIs:

- `Authorization`
- `Accept`
- `Content-Type` and `Content-Encoding`
- `User-Agent`
- OpenAI organization/project headers
- request and W3C trace correlation headers
- `x-litellm-*` extension headers

It does not forward cookies, `Host`, forwarding-chain headers, proxy credentials, `Connection`, transfer framing, or arbitrary caller headers.

Approved upstream response metadata includes content type/encoding, retry information, authentication challenge, request correlation, OpenAI/LiteLLM metadata, and rate-limit headers. Response bodies are streamed rather than accumulated in memory, preserving server-sent event behavior.

## Operational diagnosis

When `auth_rejected` increases:

1. Identify the caller from trusted gateway identity/audit context, not from the rejected token.
2. Inspect the caller's credential-selection configuration.
3. Confirm it references a LiteLLM virtual key secret, not a phone number, user ID, billing account, or provider-native key.
4. Rotate or remap the secret at its owning credential registry.
5. Test one request through Wardnet.
6. Confirm the request reaches LiteLLM and that LiteLLM performs its own key authorization.

Never resolve the alert by disabling the policy, logging the complete header, or automatically adding the `sk-` prefix.

## Verification matrix

| Case | Expected result |
|---|---|
| Missing Authorization | 401; no upstream request |
| Two Authorization headers | 401; no upstream request |
| `Basic ...` | 401; no upstream request |
| `Bearer 0610...` | 401; no token reflection; `auth_rejected` event |
| Invalid token character or misplaced padding | 401 |
| Bounded `Bearer sk-...` | Forwarded for authoritative LiteLLM validation |
| Route policy `none` | Existing route behavior preserved |
| Cookie supplied with valid key | Cookie stripped |
| SSE upstream response | Streamed with content type and rate-limit metadata |
