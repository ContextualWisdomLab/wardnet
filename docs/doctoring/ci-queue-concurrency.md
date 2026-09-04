# CI queue concurrency evidence

Wardnet's repository-owned `CI` and `Fuzz` workflows use pull-request-scoped concurrency groups so that a newer head for the same pull request can retire obsolete work without cancelling evidence for a different pull request or for default-branch, scheduled, or manually dispatched runs. `converted_to_draft` and `closed` events enter the same PR concurrency group, while the job-level guard prevents the replacement run from consuming a runner. `ready_for_review` re-enables current-head execution.

This is a queue-pressure and evidence-integrity policy, not a substitute for required security or review gates. A cancelled, skipped, queued, or stale predecessor run is never promoted to success for a newer head. The workflow must still obtain terminal evidence on the exact current head before merge.

## Research basis

Juloori et al. (2025) study large-scale continuous-integration queue scheduling at Uber. Their SubmitQueue measurements show that unnecessary or prematurely aborted speculative builds can materially increase resource consumption and waiting time; the paper reports that prioritizing likely-needed builds and pruning low-value speculation reduced CI resource use and p95 waiting time in the evaluated monorepos. Wardnet does **not** copy SubmitQueue's probabilistic scheduler. The relevant design inference is narrower: when a newer PR head or a Draft/closed transition makes an older PR execution non-authoritative, retaining both executions consumes scarce CI capacity without improving exact-head evidence.

GitHub Actions' concurrency contract provides the platform mechanism Wardnet uses for that bounded inference: jobs or workflow runs sharing a concurrency group may be cancelled when a newer run in the group is enqueued and `cancel-in-progress` is enabled. Wardnet therefore keys PR runs by workflow, repository, and PR number, while non-PR executions fall back to `run_id` so unrelated evidence lanes are not coalesced.

## Traceability and licensing

The research paper is published in the Proceedings of the 47th International Conference on Software Engineering (ICSE 2025) and the authors' arXiv version is licensed CC BY 4.0, which permits redistribution with attribution. The current automation connector can write UTF-8 repository files but cannot upload binary PDF bytes, so the citation and redistribution status are recorded here; the permissibly redistributable PDF remains an evidence-packaging follow-up rather than being represented by an invalid text-encoded `.pdf`.

### References

GitHub. (n.d.). *Control the concurrency of workflows and jobs*. GitHub Docs. https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency

Juloori, D., Lin, Z., Williams, M., Shin, E., & Mahajan, S. (2025). CI at scale: Lean, green, and fast. *Proceedings of the 47th International Conference on Software Engineering*. https://doi.org/10.48550/arXiv.2501.03440

ArXiv full text and license: https://arxiv.org/abs/2501.03440 ; https://creativecommons.org/licenses/by/4.0/
