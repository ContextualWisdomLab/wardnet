# Architecture decision records

ADR status records a decision or proposal, not proof of implementation, passing checks, integration, or release. Repository review and existing security gates remain separate.

| Record | Relationship |
| --- | --- |
| [0010](0010-adaptive-contextual-orchestrator-default.md) | Existing record, unchanged by the anti-bot ownership proposal |
| [2026-09-05 anti-bot acquisition boundary](2026-09-05-anti-bot-acquisition-boundary.md) | Proposed boundary: outbound browser acquisition/challenge handling stays outside Wardnet; Wardnet retains security admission and site-reputation/SOC policy ownership |
| [2026-09-05 outbound site reputation](2026-09-05-outbound-site-reputation-engine.md) | Separate proposed Wardnet-owned site-reputation design in PR #173; not present on this branch until that PR or a verified successor is integrated |

The dated identifier avoids allocating a sequential number over independently developed ADR work. The anti-bot proposal does not introduce a working engine or change Wardnet runtime behavior. Site-reputation implementation details remain in [Wardnet PR #173](https://github.com/ContextualWisdomLab/wardnet/pull/173) or its verified successor; the independent anti-bot design is currently incubated in [Veilpick PR #3](https://github.com/ContextualWisdomLab/Veilpick/pull/3).