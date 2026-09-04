# CI queue concurrency evidence

Wardnet's repository-owned `CI` and `Fuzz` workflows coalesce only **superseded pull-request heads**. `opened` and `synchronize` validation share a fixed, workflow-specific PR concurrency group; only a `synchronize` event may cancel work in that group. `reopened` and `ready_for_review` use run-specific groups so a state-only transition cannot discard validation for an unchanged head. `converted_to_draft` and `closed` are deliberately not cancellation triggers.

Draft work is still prevented from consuming a local Rust/fuzz runner when the event itself observes a Draft PR: the job-level guard skips `opened`, `synchronize`, `reopened`, or `ready_for_review` events whose current PR state is Draft. A later Draft `synchronize` event may cancel an older PR-group run because the commit has genuinely superseded that older head, then skips its own job. Merely converting an unchanged current head to Draft does not cancel that head's already queued/running evidence. This preserves the repository invariant that only superseded heads may be cancelled.

`Fuzz` remains path-filtered to Wardnet's fuzzable surfaces and harness. Because Draft/closed state transitions are no longer used as cancellation signals, that path filter cannot suppress a required state-transition cancellation event. The fixed `wardnet-ci` and `wardnet-fuzz` prefixes also prevent a PR from changing a workflow display name to escape or collide with another workflow's concurrency group.

This is a queue-pressure and evidence-integrity policy, not a substitute for required security or review gates. A cancelled, skipped, queued, or stale predecessor run is never promoted to success for a newer head. The workflow must still obtain terminal evidence on the exact current head before merge.

## Research basis

Juloori et al. (2025) study large-scale continuous-integration queue scheduling at Uber. Their SubmitQueue measurements show that unnecessary or prematurely aborted speculative builds can materially increase resource consumption and waiting time; the paper reports that prioritizing likely-needed builds and pruning low-value speculation reduced CI resource use and p95 waiting time in the evaluated monorepos. Wardnet does **not** copy SubmitQueue's probabilistic scheduler. The relevant design inference is narrower: when a newer commit makes an older PR execution non-authoritative, retaining both executions consumes scarce CI capacity without improving exact-head evidence. A PR state transition alone is not treated as supersession.

GitHub Actions' concurrency contract provides the platform mechanism for that bounded inference: jobs or workflow runs sharing a concurrency group may be cancelled when a newer run in the group is enqueued and `cancel-in-progress` is enabled. Wardnet therefore uses immutable workflow-specific prefixes, repository identity, and the PR number for the opened/synchronize validation lineage; state-only and non-PR executions fall back to `run_id` so unrelated or unchanged-head evidence lanes are not coalesced.

## Traceability and licensing

The research paper is published in the Proceedings of the 47th International Conference on Software Engineering (ICSE 2025), and the authors' arXiv version is licensed CC BY 4.0, which permits redistribution with attribution. The redistribution-permitted full-text PDF is required in Wardnet's evidence pack at `docs/papers/ci-at-scale-lean-green-fast-arxiv-2501.03440.pdf` before this process-change candidate is merge-ready; citation-only evidence does not satisfy that packaging gate.

### References

GitHub. (n.d.). *Control the concurrency of workflows and jobs*. GitHub Docs. https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency

Juloori, D., Lin, Z., Williams, M., Shin, E., & Mahajan, S. (2025). CI at scale: Lean, green, and fast. *Proceedings of the 47th International Conference on Software Engineering*. https://doi.org/10.48550/arXiv.2501.03440

ArXiv full text and license: https://arxiv.org/abs/2501.03440 ; https://creativecommons.org/licenses/by/4.0/
