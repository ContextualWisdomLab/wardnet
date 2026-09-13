# ADR 0008: AI SOC assist is advisory; released orchestration and human enforcement are mandatory

- Status: Accepted
- Date: 2026-08-25
- Reconciled: 2026-09-13
- Recorded from: `docs/architecture.md` AI SOC paragraph;
  `docs/security/threat-model.md` human approval boundary; optional
  `/api/soc` LLM analyze path; ADR 0010

## Context

SOC operators benefit from a short triage note on a recorded event
(likely attack class, severity judgement, recommended action). That
text is easy to mistake for an automated block or for evidence that a
model-provider integration is a Wardnet-owned security control.

Protected `main` still contains an optional OpenAI-compatible
`SocLlmConfig` hook and sends `orchestration_mode: "auto"`. That shape
records the intended delegation in ADR 0010, but a generic compatible
endpoint cannot prove that contextual-orchestrator owned model
discovery, routing, provider credentials, fallback, or orchestration.
The canonical owner currently has no immutable GitHub release, so the
generic hook is implementation history/development compatibility rather
than release evidence for a commercial LLM path.

Nelson et al. (2025) place high-impact response actions (for example
shutting down or rebuilding critical services) under leadership
decision-making and tell incident handlers to keep the ability to
**manually** select containment instead of or in addition to
automation (NIST SP 800-61r3). That is incident-handling guidance,
not a product certification.

## Decision

1. **AI SOC assist is advisory.** It may summarize an event, suggest
   a class or severity, and recommend an action.
2. **Enforcement-changing recommendations require a human.** No LLM
   output may by itself enable block mode, add a deny route, publish a
   DNSBL listing, change admission policy, or mutate gateway/SOC policy.
3. Any production or release-qualified LLM use must consume an
   **immutable released contextual-orchestrator interface** (API,
   client, schema, or runtime artifact as owned there), pinned to the
   exact released version/digest with verifiable provenance. Wardnet
   must not vendor contextual-orchestrator source, duplicate provider
   discovery/routing/fallback logic, accept provider credentials, or
   treat a mutable sibling branch as a dependency.
4. Delegate workflow depth and model selection only through that
   released contextual-orchestrator contract and the adaptive
   orchestration semantics in ADR 0010. Wardnet retains authorization,
   event/security evidence, policy, audit, operator presentation, and
   every enforcement decision.
5. Until a released owner contract exists and Wardnet pins it, the
   generic `SocLlmConfig` endpoint hook is **not release-compliant LLM
   evidence**. A release profile must leave model assist unavailable or
   fail closed rather than silently substituting a generic provider or
   repository-local orchestration implementation.
6. Current `run_from_env` does not wire `SOC_LLM_BASE_URL`; absent
   explicit in-process configuration, assist remains unavailable and
   the gateway continues to enforce operator-written policy.
7. LLM output is untrusted input. Cancellation, provider failure,
   malformed output, missing provenance, or orchestration abstention
   cannot weaken existing policy or authorize enforcement.

## Consequences

- A generic OpenAI-compatible endpoint may remain useful for bounded
  development compatibility, but it is not evidence of ADR 0010 or
  commercial release compliance.
- The contextual-orchestrator owner must publish an immutable,
  provenance-verifiable contract before Wardnet can claim a released
  production LLM integration. That owner dependency is tracked at
  `ContextualWisdomLab/contextual-orchestrator#1023` (or its verified
  successor); Wardnet must consume the resulting release rather than
  reproduce it.
- Adaptive orchestration changes inference execution, not Wardnet's
  human enforcement boundary.
- Human approval stays required even after a released orchestration
  contract exists; audit trails, rollback, and policy simulation are
  additional controls rather than permission for autonomous blocking
  (`docs/security/threat-model.md`).
- Mapping events to ATT&CK tactics is a roadmap capability, not an
  accepted automated enforcer.
- NIST SP 800-61r3 supersedes SP 800-61r2; this ADR cites r3 only.

## References

Nelson, A., Rekhi, S., Souppaya, M., & Scarfone, K. (2025).
*Incident response recommendations and considerations for
cybersecurity risk management: A CSF 2.0 community profile*
(NIST SP 800-61r3). National Institute of Standards and Technology.
https://doi.org/10.6028/NIST.SP.800-61r3

*(DOI GET returned the official PDF 2026-08-25; CSRC landing
https://csrc.nist.gov/pubs/sp/800/61/r3/final also 200. Authors and
April 2025 imprint taken from that PDF front matter.)*
