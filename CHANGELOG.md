# Changelog

All notable changes to Wardnet are documented in this file.

## [Unreleased]

### Added

- Route-level `litellm_virtual_key` authorization policy for OpenAI-compatible LiteLLM upstreams.
- Stable non-secret authentication rejection codes and RFC 6750 challenges.
- Approved request/response header forwarding for LLM APIs.
- Streaming upstream response relay for server-sent events and other long-running LLM responses.
- Security, ADR, operational, and standards-traceability documentation for the LiteLLM credential-class boundary.

### Security

- Reject phone-shaped, missing, duplicate, wrong-scheme, malformed, and oversized credentials before LiteLLM upstream I/O.
- Prevent rejected credentials and masked fragments from entering response bodies or Wardnet security events.
- Strip cookies, forwarding-chain headers, proxy credentials, host routing, transfer framing, and arbitrary caller metadata at the LLM proxy boundary.
