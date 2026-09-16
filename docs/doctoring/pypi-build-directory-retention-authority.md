# PyPI build-directory retention authority

## Decision

Wardnet Agent Artifact Admission rejects a direct `pip` or `pip3 install` intent when the caller selects pip's build-directory retention option through canonical `--no-clean` or a verified unambiguous long-option prefix beginning at `--no-cl`.

This is an argv-authority decision only. Wardnet does not choose the temporary directory, inspect retained build trees, delete filesystem content, or infer whether cleanup actually occurred. Effective workspace placement, filesystem isolation, lifecycle cleanup and recovery remain owned by `quarantine-sandbox-runtime`.

## Problem and threat

The reviewed artifact receipt authorizes a bounded installer intent. Pip's `--no-clean` changes installer cleanup behavior by retaining build directories that normal operation would remove. Allowing the caller to add that selector after review expands filesystem-retention authority without changing the approved package coordinate, digest or manifest identity.

At the pinned pip parser surface recorded by issue #335, direct pip uses Python `optparse` long-option abbreviation semantics. `--no-c` is ambiguous in the contemporaneous option set, while `--no-cl` uniquely selects `--no-clean`. The admission language therefore recognizes only the verified family `--no-cl`, `--no-cle`, `--no-clea`, and `--no-clean`; it does not use a broad prefix heuristic.

## Executed hostile RED

Test-only exact `4ca6ddb7252461c2f421cf4b0e1bd56ed6d01b16` was based on canonical Agent Artifact Admission parent `#129@a341f70d9629511c0fba0f8b5a7e042f26549f37`; production policy bytes were unchanged.

Hosted CI run `34641939332`, rust job `103403554979`, acquired a GitHub-hosted Ubuntu 24.04 runner, checked out the PR merge candidate, passed `cargo fmt --check`, and reached the locked workspace tests. The hostile contract failed on the first verified parser spelling: direct `pip install ... --no-cl` returned `Allow` where policy requires `Block`. The exact reviewed direct-pip control remained part of the same contract, so the failure is causal to the added retention authority rather than bootstrap or unrelated policy behavior.

## Minimum causal repair

The production repair adds one crate-private direct-pip classifier and wires it into the existing admission decision. A matching request is blocked with the stable `alternate_install_root` reason. The classifier requires exact `pip` or `pip3`, the `install` command, and one of the verified no-clean spellings. Ambiguous, assigned or unrelated tokens such as `--no-c`, `--no-co`, `--no-clean=false`, `--no-cleaner`, `--no-input`, and `--no-deps` do not gain no-clean semantics.

No pip execution, filesystem probing, temporary-directory selection, package analysis, network authorization, source copy, cross-service SQL or foreign runtime policy was introduced.

## Ownership boundary

Wardnet owns the pre-execution security-policy verdict that a reviewed install intent cannot gain unreviewed build-directory retention authority. `quarantine-sandbox-runtime` remains canonical owner of effective filesystem, mount, privilege, resource, ephemeral-workspace and cleanup behavior. EgressWeave remains canonical owner of outbound execution/network authorization. AppGuardrail remains canonical owner of static package/security analysis. Contextual Orchestrator remains canonical owner of LLM orchestration and provider/model execution policy.

This boundary follows least-authority design: Wardnet can deny the explicit caller request without becoming the executor or claiming facts about the resulting filesystem.

## Alternatives considered

Allowing `--no-clean` and relying only on sandbox cleanup was rejected because the reviewed admission would still authorize installer semantics that were not present in the reviewed intent. Inspecting or deleting retained directories inside Wardnet was rejected because it duplicates quarantine runtime ownership and makes the admission decision depend on mutable execution state. Matching every `--no-c*` prefix was rejected because Python `optparse` resolves only unique prefixes and the contemporaneous pip option set makes shorter prefixes ambiguous.

## Verification and integration contract

Exact approved direct `pip` and `pip3` installs remain `Allow`. Each verified `--no-clean` spelling must return `Block` with `alternate_install_root`; ambiguous `--no-c` remains a negative control. Every source or doctoring change invalidates predecessor GREEN evidence.

Stacked feature-branch children are proved by Wardnet-owned CI/Fuzz on the exact child head. Organization ruleset `18156473` applies the central Security Scan, SAST, review and CodeQL workflows to the protected default-branch integration path; those gates must be reacquired on canonical Agent Artifact Admission #129 after ordinary expected-head child integration and before protected-main merge. Child evidence is never promoted to protected-main evidence.

Issue #335 remains open until this delta reaches protected `main` or a verified complete successor.

## Traceability

- Python Software Foundation. (2026). *optparse — Parser for command line options*. Python documentation. Long options may be abbreviated only when the prefix is unambiguous.
- Python Packaging Authority. (2026). *pip command options* at the pinned source revision recorded in Wardnet issue #335. The install option surface defines `--no-clean` as the caller control for retaining build directories.
- National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218
- MITRE. (2025). *CWE-459: Incomplete Cleanup*. Common Weakness Enumeration.
- Wardnet issue #335 and Draft PR #336 retain the parser proof, hostile RED, repair lineage and exact-head integration evidence.
