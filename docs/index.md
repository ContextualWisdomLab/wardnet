# Wardnet

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ContextualWisdomLab/wardnet)

Wardnet is the Rust-first gateway and SOC control plane for ContextualWisdomLab. It owns web-managed gateway routes, request scoring, monitor/block enforcement, DNSBL publication, security-event evidence, and operator-facing readiness APIs.

## Product boundary

Wardnet deliberately does not claim complete WAF, IDS, SIEM, or SOAR coverage. Production detection and enforcement are designed to integrate proven engines and standards such as Coraza with OWASP CRS, Suricata, STIX/TAXII, MISP, and OpenCTI.

Adjacent ecosystem responsibilities remain separate:

- `pingora-gateway` owns the reusable Rust edge gateway.
- `EgressWeave` owns governed outbound authorization.
- `quarantine-sandbox-runtime` owns isolated execution.
- `appguardrail` owns scanning, SARIF evidence, and remediation.
- `contextual-orchestrator` owns model-provider discovery and routing.

Integrations must use released, versioned contracts; this repository does not copy sibling source or read sibling databases.

## Evidence

- [Architecture](architecture.md)
- [Threat model](security/threat-model.md)
- [Operations runbook](runbooks/operations.md)
- [Customer-contract readiness](commercial/2b-krw-customer-contract-readiness.md)
- [USD 20B product-quality bar](commercial/usd-20b-product-quality-bar.md)
- [Repository README](../README.md)

The protected branch remains the publication authority. An open pull request is Proposed evidence until its exact head passes required checks, receives the required review, and merges.
