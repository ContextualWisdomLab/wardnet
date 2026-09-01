# ADR 0008: AI SOC assist is advisory; enforcement changes require a human

- Status: Accepted
- Date: 2026-08-25
- Recorded from: current `main` (`docs/architecture.md` AI SOC
  paragraph; `docs/security/threat-model.md` human approval boundary;
  optional `/api/soc` LLM analyze path)

## Context

SOC operators benefit from a short triage note on a recorded event
(likely attack class, severity judgement, recommended action). That
text is easy to mistake for an automated block.

On current `main`, optional LLM assist posts one chat-completions
request through a configured OpenAI-compatible base URL. The request
sets `orchestration_mode: "auto"`, delegating model topology and
reasoning depth to contextual-orchestrator as recorded in ADR 0010,
and returns **analysis text only**. It does not upsert routes, threats,
or DNSBL entries.

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
   output may by itself enable block mode, add a deny route, or
   publish a DNSBL listing.
3. When enabled, delegate workflow depth and model selection through
   the explicit adaptive orchestration contract in ADR 0010. Wardnet
   retains authorization, evidence collection, and enforcement.
4. Leave the LLM backend **optional**. Current `main` exposes the
   `SocLlmConfig` runtime hook, but `run_from_env` does **not** yet
   wire `SOC_LLM_BASE_URL`; absent explicit in-process configuration,
   assist is unavailable and the gateway still enforces
   operator-written policy.
5. Do not treat cancelled scanner runs, unmerged drafts, or coverage
   stubs as evidence that assist is safe to auto-enforce.

## Consequences

- Operators can wire contextual-orchestrator (or another compatible
  endpoint) without giving that hook control-plane write authority. The
  current runtime sends `orchestration_mode` but cannot prove that a generic
  OpenAI-compatible endpoint honored it; such endpoints are not evidence of
  ADR 0010 compliance until an acknowledgement contract is implemented.
- Adaptive orchestration changes inference execution, not Wardnet's
  human enforcement boundary; see ADR 0010 for its accepted contract.
- Human approval stays required until audit trails, rollback, and
  policy simulation exist for machine-proposed enforcement
  (`docs/security/threat-model.md`).
- Mapping events to ATT&CK tactics is a roadmap item in
  `docs/architecture.md`; it is not an accepted automated enforcer.
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
