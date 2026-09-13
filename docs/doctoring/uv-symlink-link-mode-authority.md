# uv symlink link-mode authority

Verified 2026-09-13. This note records the vendor semantics and local security decision behind Wardnet's Agent Artifact Admission handling of `uv pip install --link-mode=symlink`. It does not claim control of uv's cache, target filesystem, or execution sandbox; those remain executor/quarantine concerns outside Wardnet's admission-evidence boundary.

## Security decision

Astral documents `uv pip install [OPTIONS] ...` and the `--link-mode` option for choosing how installed package files are materialized from uv's global cache. The documented `symlink` mode symbolically links installed packages to cache content, and Astral warns that this tightly couples the target environment to the cache: clearing the cache can break installed packages. A reviewed package coordinate and digest therefore do not by themselves authorize a caller to change the materialization relationship between the approved artifact and the target environment.

Wardnet classifies an explicit `--link-mode=symlink` or `--link-mode symlink` on the active `uv pip install` command as separate `ArtifactNotApproved` evidence. The classifier reuses the shared `uv_active_command_index` parser so documented top-level uv options before `pip` cannot erase that causal evidence. This does **not** widen Wardnet's supported install grammar: a submitted form such as `uv --color never pip install ... --link-mode=symlink` remains generically forbidden while also preserving the specific symlink-materialization reason.

The classifier is deliberately command-bounded. `uv pip sync`, delegated child argv, and nearby option spellings do not inherit `uv pip install` link-mode authority. Wardnet does not execute uv, inspect or mutate uv's cache, create links, or decide filesystem isolation. The executor and quarantine runtime remain responsible for controlled execution and filesystem behavior after an intent is admitted.

## Local evidence

- `crates/agent-artifact-admission/src/uv_link_mode_authority.rs` parses the active uv command with `policy::uv_active_command_index`, requires exact `pip` followed by exact `install`, and then inspects only that install argument slice for the documented symlink forms.
- `crates/agent-artifact-admission/tests/uv_symlink_link_mode_authority_contract.rs` covers attached and separate symlink forms, reviewed top-level uv options, and a nearby spelling control.
- Issue #401 and PR #402 retain the hostile RED→GREEN evidence for the parser-phase gap. The hosted RED on exact test-only head `01d0a524da802720135a0be8ba6d62e88022e7ea` reached the new contract and returned only `ForbiddenCommand`, demonstrating loss of the separate `ArtifactNotApproved` reason before the production repair.

## Standards traceability

NIST SP 800-218 SSDF 1.1 recommends integrating secure-development practices that reduce vulnerabilities and address their root causes. Wardnet applies that principle here by fixing the shared parser-phase cause rather than adding a one-off command string exception. This note does not assert NIST certification or full SSDF conformance.

As of 2026-09-13, NIST lists SP 800-218 as the final SSDF Version 1.1 publication and SP 800-218 Rev. 1 / SSDF Version 1.2 as a draft. Wardnet therefore cites Version 1.1 as the final baseline and treats the draft separately.

## APA 7 references

Astral Software, Inc. (2026). *Commands: uv documentation.* https://docs.astral.sh/uv/reference/cli/

Astral Software, Inc. (2026). *Settings: uv documentation.* https://docs.astral.sh/uv/reference/settings/

Scarfone, K., Souppaya, M., & Dodson, D. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities (NIST SP 800-218).* National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218

National Institute of Standards and Technology. (2026). *Secure Software Development Framework: Publications.* https://csrc.nist.gov/projects/ssdf/publications
