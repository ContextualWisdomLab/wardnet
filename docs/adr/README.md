# Architecture Decision Records

This directory records **accepted** architecture decisions that are already
true on current `main`. It does not propose new product work.

Narrative sources on `main`:

- [`docs/architecture.md`](../architecture.md) — component map, security
  boundaries, and adapter roadmap
- [`docs/fuzzing.md`](../fuzzing.md) — untrusted-input fuzz targets and
  property-test mirror
- Repository `README.md` — operator-facing gateway, DNSBL, and workspace notes

Each ADR is **Accepted**. Follow-ups named in an ADR (in-process Coraza
embedding, Hickory DNS authoritative serving, live MISP REST pull, live
OpenCTI GraphQL pull, a production database) are **not** accepted on `main`.

wardnet is a standalone leaf: the binary must run by itself. Sibling
ContextualWisdomLab products (naruon, gyeot, contextual-orchestrator,
Clearfolio) are optional HTTP or contract callers, not required checkouts.

## Series

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-standalone-rust-gateway-workspace-core.md) | Standalone Rust gateway with in-workspace `waf-ids-core` | Accepted |
| [0002](0002-optional-json-state-standalone-durability.md) | Optional JSON state for standalone durability | Accepted |
| [0003](0003-owasp-crs-coraza-waf-authority.md) | OWASP CRS / Coraza as WAF authority | Accepted |
| [0004](0004-rfc-5782-style-dnsbl-zone-export.md) | RFC 5782-style DNSBL zone export | Accepted |
| [0005](0005-coverage-guided-fuzzing-untrusted-inputs.md) | Coverage-guided fuzzing of untrusted-input surfaces | Accepted |
| [0006](0006-admin-token-threat-intel-document-ingest.md) | Admin-token threat-intel document ingest | Accepted |
| [0007](0007-localhost-default-bind-remote-management.md) | Localhost default bind; remote management requires token plus external TLS/identity | Accepted |
| [0008](0008-ai-soc-assist-advisory-human-enforcement.md) | AI SOC assist is advisory; enforcement changes require a human | Accepted |
| [0010](0010-adaptive-contextual-orchestrator-default.md) | SOC analysis delegates default execution to contextual-orchestrator auto | Accepted |

## Citation policy

References use APA 7th. Every external locator was fetched live on
2026-08-25. Informational RFCs stay labeled informational. Drafts,
unmerged pull requests, and unpublished scans are not cited as papers or
standards. Local PDF copies are attached only when redistribution is
permissible; otherwise the ADR cites, links, and summarizes the source
without vendoring the full text.

## Template

```markdown
# ADR NNNN: Title

- Status: Accepted
- Date: YYYY-MM-DD
- Recorded from: current `main` (path list)

## Context
## Decision
## Consequences
## References
```
