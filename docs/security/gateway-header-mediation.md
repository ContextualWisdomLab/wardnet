# Gateway header mediation contract

Status: candidate security contract for PR #441; not released or authoritative on the protected branch until that PR is merged.

Wardnet owns the generic gateway/SOC mediation boundary. This contract is deliberately narrower than an HTTP-transparent proxy: it preserves only application metadata required by the buyer path and rejects or removes transport, framing, management, and proxy authority that must not cross the gateway trust boundary. Egress authorization, sandbox isolation, LLM routing, and application guardrail semantics remain with their canonical owner repositories.

## Request boundary

The generic gateway admits only `Content-Type`, `Accept`, and bounded `X-Wardnet-App-Meta` values to the routed upstream. `X-Admin-Token`, `Authorization`, cookies, proxy credentials, client-supplied forwarding identity, `Host`, framing fields, upgrades, and other unlisted fields are not forwarded.

`Content-Type` and `X-Admin-Token` are treated as security-relevant singletons at this boundary. Duplicate instances fail closed with `400 Bad Request`. The aggregate byte length of `X-Wardnet-App-Meta` is capped at 16,384 bytes before route-upstream contact. Any field nominated by `Connection` is removed even if that field would otherwise be admitted.

This follows RFC 9110 section 7.6.1: an intermediary must parse `Connection`, remove every field named by a connection option, and remove `Connection` itself before forwarding. The allowlist is an intentional Wardnet policy restriction rather than an attempt to redefine HTTP semantics.

## Response boundary

Wardnet reconstructs the downstream response from an explicit response allowlist. The current candidate admits `Content-Type`, bounded `X-Wardnet-App-Meta`, `Location`, `Retry-After`, and `WWW-Authenticate`; it does not reflect `Connection`, fields named by `Connection`, proxy-authentication fields, upgrades, cookies, or other unadmitted authority.

An invalid admitted upstream header envelope fails closed as `502 Bad Gateway`. `Content-Type` is currently enforced as a singleton. Response-singleton hardening for `Location` and `Retry-After` is tracked separately so this PR does not silently expand its causal scope: RFC 9110 sections 10.2.2 and 10.2.3 define each with a single field value grammar.

`Content-Encoding` is representation metadata under RFC 9110 section 8.4, not hop-by-hop metadata. It is therefore a separate follow-on acceptance gap rather than something Wardnet may drop while relaying coded bytes. Transparent decompression is not an acceptable shortcut unless every affected representation field is transformed consistently.

## Acceptance evidence

The hostile buyer suite in `tests/gateway_header_mediation.rs` must exercise a real loopback upstream, not a mocked header helper alone. GREEN requires all of the following on one exact head:

- admitted request media type, content negotiation, and bounded repeated application metadata survive the gateway;
- duplicated management credentials, duplicated request `Content-Type`, and oversized application metadata fail before the routed upstream receives the request;
- `Host`, framing authority, credentials, cookies, proxy authority, forwarding identity, upgrades, and dynamically connection-nominated fields do not cross the request boundary;
- admitted upstream representation metadata survives the response boundary while fixed and dynamically nominated hop-by-hop/security authority does not;
- repository CI, fuzzing, security/SAST/CodeQL governance, coverage/rustdoc evidence, buyer-path latency evidence, and parent/base compatibility are reacquired for the exact candidate head.

A workflow result that is queued, `action_required`, skipped without jobs, or attached to a predecessor SHA is not transferable GREEN evidence.

## References

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP semantics* (RFC 9110). RFC Editor. https://www.rfc-editor.org/rfc/rfc9110

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP/1.1* (RFC 9112). RFC Editor. https://www.rfc-editor.org/rfc/rfc9112
