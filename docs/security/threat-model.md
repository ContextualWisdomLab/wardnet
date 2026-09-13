# Threat Model

## Assets

- Gateway route configuration
- Threat indicators and DNSBL entries
- Security event history
- License and tenant metadata
- Admin token
- Upstream service availability
- State file integrity
- Agent Artifact Admission policy, immutable artifact digest identity, reviewed workspace-manifest identity, and evaluated evidence set
- Agent Artifact Admission decision and admission receipt, including the policy/evidence identities that justify an allow or deny

## Trust Boundaries

- Public HTTP clients enter through `/gateway/{path}`.
- Operators use management APIs and the embedded admin console.
- Upstream services are outside the process trust boundary.
- The state file is trusted only after JSON deserialization succeeds.
- A non-loopback listener is untrusted until a write-capable admin principal exists in the credential registry. This follows the fail-secure and authenticator-management posture documented in the production guide and runbook: start closed, bootstrap secrets into the registry, then expose the listener only after a usable write credential exists.
- Threat feed import payloads are untrusted operator-supplied data.
- Agent Artifact Admission treats installer intent, artifact coordinates, workspace-manifest identity, artifact digest values, and submitted foreign-owner evidence as untrusted until Wardnet validates their structure, binding, policy identity, and freshness. An allow receipt authorizes only Wardnet admission; it is not evidence that bytes were fetched, a hostile workload was isolated, egress was authorized, an LLM/tool workflow ran, or an application guardrail executed.
- `quarantine-sandbox-runtime` remains the canonical owner of hostile-workload isolation and artifact-analysis execution; `EgressWeave` owns outbound destination/transport authorization; `contextual-orchestrator` owns LLM/model/tool orchestration through its released API; `appguardrail` owns its application/agent guardrail implementation and evidence. Wardnet validates released evidence/contracts from these owners but does not copy their implementation logic or query their private persistence.
- A mutable branch, pull-request head, sibling working tree, or other non-released foreign-owner state is development evidence only. Security-critical Agent Artifact Admission must fail closed when a required immutable/released owner contract or verifiable evidence receipt is absent, malformed, stale, or bound to a different artifact/policy identity.

## Security Grounding

The startup gate and secret-handling path in this PR are aligned with NIST guidance that authentication secrets need lifecycle control and protected handling, and that authenticators should fail securely instead of silently degrading to weaker access. Wardnet applies that by preferring `WAF_IDS_CREDENTIALS_PATH`, allowing env only as bootstrap transport, and refusing non-loopback readiness when no usable write credential can be presented through `X-Admin-Token`. The operator recovery path is documented in [docs/deployment/production.md](../deployment/production.md), and the accepted bootstrap sources and RBAC shapes are documented in [docs/runbooks/operations.md](../runbooks/operations.md).

Agent Artifact Admission adds a software-supply-chain evidence boundary. NIST SP 800-218 Version 1.1 PS.3.2 calls for collecting, safeguarding, maintaining, and sharing software-component provenance and protecting its integrity; Wardnet applies that principle by binding admission to immutable artifact/evidence identities instead of treating a package name, mutable ref, or unauthenticated owner assertion as sufficient proof. NIST SP 800-161 Rev. 1 Update 1 is the current final NIST C-SCRM publication and frames malicious, counterfeit, vulnerable, and insufficiently understood third-party components/services as supply-chain risks requiring explicit identification, assessment, and mitigation. SP 800-218 Rev. 1 / SSDF Version 1.2 remains an initial public draft and is not promoted here as final authority.

### Research artifact redistribution assessment

The authentication-specific NIST SP 800-57 Part 1 Rev. 5 and NIST SP 800-63B sources below remain linked to their authoritative publication records and summarized here; this PR does not republish copies of those two PDFs because the exact retrieved artifacts were not independently assessed for redistribution during this change. Separately, the branch retains `docs/papers/nist-sp-800-218-ssdf.pdf` as redistributable NIST SP 800-218 Version 1.1 evidence for the secure-development, credential-bootstrap, and software-provenance boundary. Its authoritative source, redistribution basis, attribution, and final-versus-draft status are recorded in [docs/doctoring/fail-closed-management-auth.md](../doctoring/fail-closed-management-auth.md). The repository copy is evidence only and does not supersede NIST's publication.

## Primary Threats

| Threat | Impact | Current Control | Required Hardening |
| --- | --- | --- | --- |
| Unauthorized management write | Route takeover or false blocking | `X-Admin-Token` write gate; multi-token RBAC with actor labels and readonly role; fail-closed startup on non-loopback bind without a write-capable principal; `401` vs `403` without revealing the expected role; audit log for successful writes | SSO/OIDC, mTLS or identity proxy, SCIM |
| Malicious threat feed import | False positives or broad blocks | Validation, route-scoped enforcement | Source signing, feed confidence, staged promotion |
| State file corruption | Startup failure or stale policy | JSON parse failure surfaces startup error | Database, backup, schema migration |
| Upstream SSRF through routes | Internal network exposure | Upstream scheme validation | Released EgressWeave boundary for destination/address/redirect/proxy/TLS enforcement |
| Gateway DoS | Availability loss | Rust memory safety, event retention limit | Rate limits, body limits, async event sink |
| DNSBL abuse | Reputation damage | Loopback response-code validation | Authoritative DNS service, signing, publisher workflow |
| Secret disclosure | Admin compromise | Support bundle excludes admin token; secrets bootstrapped into credential registry (`WAF_IDS_CREDENTIALS_PATH` preferred over long-lived env); health exposes source label only | External secret manager / SSO, rotation, access review |
| Artifact identity substitution | A reviewed package coordinate is replaced by different bytes, registry/owner identity, workspace manifest, or installer interpretation while retaining apparent admission | Agent Artifact Admission binds exact structured coordinates, artifact digest, workspace-manifest digest, submitted argv, policy identity, and required evidence; mismatches deny | Released retrieval/executor evidence must cryptographically bind the retrieved bytes and effective execution input back to the same admission identity |
| Forged or stale foreign-owner evidence | A sandbox/egress/orchestration/guardrail claim is replayed, fabricated, or attached to a different artifact/policy decision | Wardnet consumes foreign evidence only through released/versioned contracts, validates required identity/freshness fields, and fails closed on absent, malformed, stale, unverifiable, or mutable-branch evidence | Cryptographic issuer identity, anti-replay/expiry semantics, immutable release provenance, and conformance tests per owner contract |
| Admission-authority confusion | A Wardnet allow receipt is misread as proof that hostile execution, egress, installation, LLM/tool orchestration, or guardrail enforcement occurred | Receipt semantics are explicitly limited to Wardnet admission; canonical foreign-owner responsibilities remain separate | End-to-end buyer/operator evidence should correlate distinct owner receipts without collapsing them into one authority claim |

## Human Approval Boundary

AI SOC recommendations may explain, summarize, or suggest actions, but enforcement-changing decisions must remain human-approved until audit trails, rollback, and policy simulation are implemented. Any future LLM-backed triage must use the released `contextual-orchestrator` API; model output cannot substitute for deterministic Agent Artifact Admission evidence or foreign-owner receipts.

## References

Barker, E. (2020). *Recommendation for key management: Part 1 - General* (NIST SP 800-57 Part 1 Rev. 5). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-57pt1r5

Boyens, J., Smith, A., Bartol, N., Winkler, K., Holbrook, A., & Fallon, M. (2022, updated 2024). *Cybersecurity supply chain risk management practices for systems and organizations* (NIST SP 800-161 Rev. 1 Update 1). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-161r1-upd1

Grassi, P. A., Garcia, M. E., & Fenton, J. L. (2020). *Digital identity guidelines: Authentication and lifecycle management* (NIST SP 800-63B). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-63b

Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218
