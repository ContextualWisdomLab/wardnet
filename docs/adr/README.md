# Architecture Decision Records

ADR status records an architecture decision, not proof that implementation, checks, protected integration, packaging, or release are complete. Repository review, security gates, release evidence, and code-current implementation truth remain separate.

Narrative sources include:

- [`docs/architecture.md`](../architecture.md) — component map, security boundaries, and adapter roadmap
- [`docs/fuzzing.md`](../fuzzing.md) — untrusted-input fuzz targets and property-test mirror
- repository `README.md` — operator-facing gateway, DNSBL, deployment, and workspace notes
- [`docs/security/threat-model.md`](../security/threat-model.md) — trust and enforcement boundaries

Wardnet remains a standalone security leaf for its owned gateway/SOC control plane, Agent Artifact Admission, security evidence, and policy. Sibling owners are consumed only through their released contracts; their canonical implementation is not copied into this repository.

## Series

| ADR | Title | Status / relationship |
| --- | --- | --- |
| [0001](0001-standalone-rust-gateway-workspace-core.md) | Standalone Rust gateway with in-workspace `waf-ids-core` | Accepted |
| [0002](0002-optional-json-state-standalone-durability.md) | Optional JSON state for standalone durability | Accepted |
| [0003](0003-owasp-crs-coraza-waf-authority.md) | OWASP CRS / Coraza as WAF authority | Accepted |
| [0004](0004-rfc-5782-style-dnsbl-zone-export.md) | RFC 5782-style DNSBL zone export | Accepted |
| [0005](0005-coverage-guided-fuzzing-untrusted-inputs.md) | Coverage-guided fuzzing of untrusted-input surfaces | Accepted |
| [0006](0006-admin-token-threat-intel-document-ingest.md) | Admin-token threat-intel document ingest | Accepted |
| [0007](0007-localhost-default-bind-remote-management.md) | Localhost default bind; remote management requires write-capable auth plus external TLS/identity | Accepted; protected #155 supplies the fail-closed public-bind/auth gate, while external TLS/enterprise identity remain deployment controls |
| [0008](0008-ai-soc-assist-advisory-human-enforcement.md) | AI SOC assist is advisory; released orchestration and human enforcement are mandatory | Accepted boundary; released contextual-orchestrator consumption remains an implementation/release dependency until an immutable owner release exists |
| [0010](0010-adaptive-contextual-orchestrator-default.md) | SOC analysis delegates default execution to contextual-orchestrator auto | Existing accepted record |
| [2026-09-05 anti-bot acquisition boundary](2026-09-05-anti-bot-acquisition-boundary.md) | Outbound browser acquisition/challenge handling stays outside Wardnet; Wardnet retains security admission and site-reputation/SOC policy ownership | Proposed boundary; no runtime engine implied |
| 2026-09-05 outbound site reputation | Separate Wardnet-owned site-reputation design in [PR #173](https://github.com/ContextualWisdomLab/wardnet/pull/173) | Proposed; no relative file link until protected integration or verified successor |

Sequential ADRs and dated ADRs coexist because independently developed decision records must not be renumbered merely to obtain a contiguous series.

## Citation policy

References use APA 7th. External locators recorded by these ADRs were live-checked on their stated verification dates. Informational RFCs remain labeled informational. Drafts, unmerged pull requests, and unpublished scans are not represented as released standards or integrated product evidence. Local PDF copies are retained only when redistribution is permissible; otherwise the ADR links and summarizes the source without vendoring the full text.

## Template

```markdown
# ADR NNNN: Title

- Status: Accepted | Proposed | Superseded
- Date: YYYY-MM-DD
- Recorded from: protected source / path list

## Context
## Decision
## Consequences
## References
```
