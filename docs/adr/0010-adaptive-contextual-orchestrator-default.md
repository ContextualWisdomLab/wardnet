# ADR-0010: SOC analysis delegates default execution to contextual-orchestrator auto

- Status: Accepted
- Date: 2026-08-16

## Context

Wardnet's optional SOC analysis endpoint calls the organization LLM gateway, but a
model/messages-only request leaves policy implicit and can collapse into a fixed
single-worker path. Security analysis ranges from bounded enrichment to high-risk,
multi-step investigation. The edge gateway must not hard-code one provider, one
model, one topology, or one reasoning budget for every incident.

The orchestration literature also distinguishes delegation policy from the workers
that perform the task. TRINITY assigns Thinker, Worker, and Verifier roles turn by
turn; Conductor learns communication topologies and targeted worker instructions;
and Fugu adapts the resulting scaffold to the query. These results support an
adaptive default, but they do not authorize the orchestrator to own Wardnet's
security evidence, permissions, audit trail, or operator decision.

## Literature-to-decision mapping

| Source | Mechanism | Reported ablation/metric | Decision item it grounds |
| --- | --- | --- | --- |
| Xu et al. (2025), *TRINITY* | A lightweight (~0.6B parameter) coordinator assigns Thinker/Worker/Verifier roles turn-by-turn without modifying constituent model weights. | 86.2% pass@1 on LiveCodeBench at publication; the ablation attributes the gain to the coordinator's hidden-state contextualization versus RL/imitation-learning coordinators under the same budget. | Decision item 2 (role-separated worker and verifier execution) -- justifies delegating *when* to add an independent checking role to the orchestrator rather than hard-coding it in Wardnet. |
| Nielsen et al. (2025), *Conductor* | A 7B RL-trained coordinator adapts topology to task difficulty: single-query for factual tasks, planner-executor-verifier pipelines for hard tasks, with "Recursive Test-Time Scaling" (the coordinator can select itself as a worker for self-correction). | Record-setting 83.9% LiveCodeBench and 87.5% GPQA-Diamond; measured cost-efficiency gains over Mixture-of-Agents baselines. | Decision item 3 (conducted/recursive workflow for complex investigations) -- the query-adaptive depth and recursive self-correction are exactly the "decomposition, additional evidence, or iterative verification" case this item reserves for the orchestrator, not Wardnet. |
| Tang et al. (2026), *Sakana Fugu* | Fugu/Fugu-Ultra devise dynamic agentic scaffolds (large-scale fine-tuning + evolutionary search + RL) that vary with the query, orchestrating a team of diverse SOTA models. | State-of-the-art on SWE-Bench Pro, Terminal-Bench, LiveCodeBench, GPQA-Diamond, and Humanity's Last Exam; training explicitly optimizes the performance/latency trade-off via evolutionary search. | Decision item 1 (a quality-sufficient single route for bounded, low-ambiguity enrichment) and the "quality and safety take precedence over latency" rule -- query-adaptive scaffolding is the mechanism that keeps bounded events on a cheap route without Wardnet pre-selecting depth. |
| Omidvar & Akhlaghi (2026) | Models LLM sampling as a discrete stochastic channel, unifying retry/majority-vote/self-consistency into six operators, plus a cost-aware semantic-nearest-neighbor router with a single Lagrangian parameter traversing the quality-cost Pareto frontier. | ~56% lower normalized cost at matched quality, and ~7% quality improvement at matched cost (26% over single-shot), on MMLU/GSM8K/HumanEval. | The cost/quality tie-breaking rule ("known cost may break ties only after capability and safety constraints") -- grounds treating cost as a Pareto-frontier parameter subordinate to quality/safety, not an independent optimization target. |

The scheduled evaluations required by the Decision section (comparing single-route,
worker-verifier, and deeper orchestration modes on grounded SOC outcomes) are the
Wardnet-side analogue of each paper's own ablation methodology, applied to this
system's incident corpus instead of LiveCodeBench/GPQA/MMLU.

## Decision

The SOC request explicitly includes `orchestration_mode: "auto"`. The central
orchestrator may select, within its published contract:

1. a quality-sufficient single route for bounded, low-ambiguity enrichment;
2. role-separated worker and verifier execution when independent checking is
   warranted; or
3. a conducted or recursive workflow for complex investigations that require
   decomposition, additional evidence, or iterative verification.

Role-specific reasoning effort, workflow depth, tool access, and stopping policy are
owned by contextual-orchestrator. Quality and safety requirements take precedence
over latency. Known cost may break ties only after capability and safety constraints;
unpriced providers are not treated as free. Scheduled evaluations must compare the
single-route, worker-verifier, and deeper orchestration modes so that increased
inference depth is retained only when it improves grounded SOC outcomes.

Wardnet retains WAF/IDS evidence collection, authorization, bounded request handling,
audit records, security-domain validation, and operator presentation. The
orchestrator receives only the bounded event representation constructed by Wardnet,
and its response remains untrusted analysis until Wardnet validates and presents it.
Explicit fixed modes remain controlled experiments and rollback controls, not the
product default. Unsupported orchestration capabilities or malformed responses fail
closed rather than silently changing the security decision path.

## Consequences

- Adding or removing worker models does not change the Wardnet API contract.
- The gateway continues to make enforcement decisions from deterministic Wardnet
  evidence; LLM output cannot directly block, allow, mutate policy, or obtain an
  administrative capability.
- Audit and evaluation evidence must identify the selected orchestration mode and
  model roles without copying secrets or unrelated personal data.
- A future live-model test lane must measure grounding, unsupported-claim rate,
  decision consistency, and the marginal benefit of deeper orchestration on a fixed
  incident corpus.

## References

Nielsen, S., Cetin, E., Schwendeman, P., Sun, Q., Xu, J., & Tang, Y. (2025).
*Learning to orchestrate agents in natural language with the Conductor* [Preprint].
arXiv. https://doi.org/10.48550/arXiv.2512.04388

Omidvar, H., & Akhlaghi, V. (2026). *A communication-theoretic framework for LLM
agents: Cost-aware adaptive reliability* [Preprint]. arXiv.
https://doi.org/10.48550/arXiv.2605.09121

Tang, Y., Cetin, E., Xu, J., Sun, Q., Nielsen, S., Richard, V., Goda, H., Tymchenko,
I., Nguyen, N., Lee, H., Ashiga, M., Kotyan, S., Kuroki, S., & Clanuwat, T. (2026).
*Sakana Fugu technical report* [Technical report]. arXiv.
https://doi.org/10.48550/arXiv.2606.21228

Xu, J., Sun, Q., Schwendeman, P., Nielsen, S., Cetin, E., & Tang, Y. (2025).
*TRINITY: An evolved LLM coordinator* [Preprint]. arXiv.
https://doi.org/10.48550/arXiv.2512.04695
