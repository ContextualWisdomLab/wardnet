# Changelog

All notable changes to Wardnet are documented in this file.

## [Unreleased]

### Added

- Dedicated `litellm-virtual-key-proxy` Rust binary for deployment in front of an OpenAI-compatible LiteLLM gateway.
- Stable non-secret authentication rejection codes and RFC 6750 challenges.
- Fixed-upstream HTTPS configuration, no-redirect transport, and bounded request bodies.
- Approved request/response header projection for LLM APIs.
- Streaming upstream response relay for server-sent events and other long-running LLM responses.
- Secret-free structured authentication and transport events.
- Health endpoint exposing policy, upstream origin, and body-limit state without performing a billable model call.
- Security, ADR, operational, and standards-traceability documentation for the LiteLLM credential-class boundary.

### Security

- Reject phone-shaped, missing, duplicate, wrong-scheme, malformed, and oversized credentials before LiteLLM upstream I/O.
- Prevent rejected credentials and masked fragments from entering response bodies or structured proxy events.
- Strip cookies, forwarding-chain headers, proxy credentials, host routing, transfer framing, and arbitrary caller metadata at the LLM proxy boundary.
- Reject upstream URLs containing credentials, queries, or fragments; require HTTPS except loopback tests; disable redirect following.
