# Architecture decision records

ADR status records a decision or proposal, not proof of implementation, passing checks, integration or release. Repository review and existing security gates remain separate.

| Record | Relationship |
| --- | --- |
| [0010](0010-adaptive-contextual-orchestrator-default.md) | Existing record, unchanged by the access/reputation proposal |
| [2026-09-05](2026-09-05-independent-access-and-reputation-engines.md) | Proposed boundary: independent outbound anti-bot and site reputation engines; Wardnet supplies optional scoped observations only |

The dated identifier avoids allocating a sequential number over independently developed ADR work. The companion [Veilpick PR #3](https://github.com/ContextualWisdomLab/Veilpick/pull/3) owns the detailed proposed engine designs. Neither proposal introduces a working engine or changes Wardnet runtime behavior.
