# Architecture decision records

ADR status records a decision or proposal, not proof of implementation, passing checks, integration, or release. Repository review and existing security gates remain separate.

| Record | Relationship |
| --- | --- |
| [0010](0010-adaptive-contextual-orchestrator-default.md) | Existing record, unchanged by the anti-bot ownership proposal |
| [2026-09-05 anti-bot acquisition boundary](2026-09-05-anti-bot-acquisition-boundary.md) | Proposed boundary: outbound browser acquisition/challenge handling stays outside Wardnet; Wardnet retains security admission and site-reputation/SOC policy ownership |
| 2026-09-05 outbound site reputation | Separate proposed Wardnet-owned site-reputation design in [PR #173](https://github.com/ContextualWisdomLab/wardnet/pull/173); no relative file link is published until that PR or a verified successor is integrated |
| [2026-09-08 reputation source publication transaction boundary](2026-09-08-reputation-source-publication-transaction-boundary.md) | Proposed durable-state boundary: atomic evidence/LKG publication through a least-privilege PostgreSQL capability; production authority remains blocked on #80/#192 deployment, pooling, recovery and release acceptance |
| [2026-09-09 reputation foundation migration atomicity](2026-09-09-reputation-foundation-migration-atomicity.md) | Proposed migration boundary: 0001–0003 forward DDL is failure-atomic and replays only from a supported predecessor state |
| [2026-09-09 reputation publication recovery order](2026-09-09-reputation-publication-recovery-order.md) | Proposed recovery boundary: post-reapply authority reconverges from the canonical role installer while missing publication evidence remains fail closed until explicitly restored |

The dated identifiers avoid allocating a sequential number over independently developed ADR work. The anti-bot proposal does not introduce a working engine or change Wardnet runtime behavior. Site-reputation implementation details remain in [Wardnet PR #173](https://github.com/ContextualWisdomLab/wardnet/pull/173) or its verified successor; the independent anti-bot design is currently incubated in [Veilpick PR #3](https://github.com/ContextualWisdomLab/Veilpick/pull/3). The PostgreSQL ADRs record implemented Draft candidates but remain Proposed until the stacked PostgreSQL authority is integrated and released.
